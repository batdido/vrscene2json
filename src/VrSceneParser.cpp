#define MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#include "VrSceneParser.h"
#include "miniz.h"
#include <cstring>
#include <cctype>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <cmath>

// ── helpers ──────────────────────────────────────────────────────────────

static inline bool is_id_char(char c) {
    return std::isalnum((unsigned char)c) || c == '_' || c == '@';
}

static std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (unsigned char)s[b] <= ' ') ++b;
    while (e > b && (unsigned char)s[e - 1] <= ' ') --e;
    return s.substr(b, e - b);
}

static std::string trim_right(const std::string& s) {
    size_t e = s.size();
    while (e > 0 && (unsigned char)s[e - 1] <= ' ') --e;
    return s.substr(0, e);
}

// strip C++ style // comments, careful with strings
static std::string strip_comments(const std::string& line) {
    bool in_str = false;
    for (size_t i = 0; i + 1 < line.size(); ++i) {
        if (line[i] == '"') in_str = !in_str;
        else if (!in_str && line[i] == '/' && line[i + 1] == '/')
            return line.substr(0, i);
    }
    return line;
}

// ── base64 encoder ───────────────────────────────────────────────────────

static const char b64_enc_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)bytes[i] << 16;
        if (i + 1 < len) v |= (uint32_t)bytes[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)bytes[i + 2];
        out += b64_enc_table[(v >> 18) & 0x3F];
        out += b64_enc_table[(v >> 12) & 0x3F];
        out += (i + 1 < len) ? b64_enc_table[(v >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? b64_enc_table[v & 0x3F] : '=';
    }
    return out;
}

// ── base64 decode ────────────────────────────────────────────────────────

static const unsigned char b64_dec[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,
    52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0
};

static std::vector<uint8_t> base64_decode(const std::string& s) {
    // Count valid chars to estimate output size
    size_t valid = 0;
    for (char c : s) {
        if (c == '=') break;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/')
            ++valid;
    }
    if (valid == 0) return {};
    std::vector<uint8_t> out(valid * 3 / 4);
    size_t j = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        unsigned char v = b64_dec[(unsigned char)c];
        // v == 0 could be either a valid 'A' or junk; check range
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/'))
            continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (j < out.size())
                out[j++] = (uint8_t)(buf >> bits);
            buf &= (1 << bits) - 1;
        }
    }
    return out;
}

// ── hex decode ───────────────────────────────────────────────────────────

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0;
}

static std::vector<uint8_t> hex_decode(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back((uint8_t)((hex_nibble(s[i]) << 4) | hex_nibble(s[i + 1])));
    return out;
}

// ── zlib decompression via tinfl ─────────────────────────────────────────

static bool decompress_zlib(const void* src, size_t src_len,
                            void* dst, size_t dst_len) {
    size_t actual = tinfl_decompress_mem_to_mem(
        dst, dst_len, src, src_len,
        TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    return actual == dst_len;
}

// ── ZIPB decode ──────────────────────────────────────────────────────────

static std::vector<uint8_t> zipb_decode(const std::string& s) {
    // format: "ZIPB" + 16 hex header + base41 data
    // header: 4 bytes LE decompressed_size + 4 bytes LE compressed_base41_chars
    // Not strictly needed; we just process all base41 chars.
    if (s.size() < 20) return {};
    std::string data = s.substr(20);  // skip "ZIPB" + 16 hex

    // base41 alphabet: A-Z=0-25, 0-9=26-35, a-e=36-40
    auto base41_val = [](char c) -> uint32_t {
        if (c >= 'A' && c <= 'Z') return (uint32_t)(c - 'A');
        if (c >= '0' && c <= '9') return (uint32_t)(c - '0' + 26);
        if (c >= 'a' && c <= 'e') return (uint32_t)(c - 'a' + 36);
        return 0;
    };

    size_t ng = data.size() / 3;
    std::vector<uint8_t> tmp(ng * 2);  // 3 base41 chars -> 2 bytes
    for (size_t i = 0; i < ng; ++i) {
        uint32_t c0 = base41_val(data[i * 3]);
        uint32_t c1 = base41_val(data[i * 3 + 1]);
        uint32_t c2 = base41_val(data[i * 3 + 2]);
        uint32_t v = c2 * 1681 + c1 * 41 + c0;  // 41^2 = 1681
        tmp[i * 2] = (uint8_t)(v & 0xFF);
        tmp[i * 2 + 1] = (uint8_t)((v >> 8) & 0xFF);
    }

    std::vector<uint8_t> result;
    // Try to read decompressed size from header
    uint32_t expected_size = 0;
    if (s.size() >= 20) {
        std::string hdr = s.substr(4, 16);
        auto h = hex_decode(hdr);
        if (h.size() >= 8) {
            expected_size = (uint32_t)h[0] | ((uint32_t)h[1] << 8) |
                           ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
        }
    }

    if (expected_size > 0 && expected_size < 1024 * 1024 * 128) {
        result.resize(expected_size);
        if (!decompress_zlib(tmp.data(), tmp.size(), result.data(), result.size()))
            result.clear();
    } else {
        // fallback: allocate big buffer and try decompress
        result.resize(128 * 1024 * 1024);
        size_t actual = tinfl_decompress_mem_to_mem(
            result.data(), result.size(), tmp.data(), tmp.size(),
            TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        if (actual != TINFL_DECOMPRESS_MEM_TO_MEM_FAILED && actual > 0)
            result.resize(actual);
        else
            result.clear();
    }
    return result;
}

// ── ZIPC decode ──────────────────────────────────────────────────────────

static std::vector<uint8_t> zipc_decode(const std::string& s) {
    // format: "ZIPC" + 8 hex (4B LE decomp_size) + 8 hex (4B LE comp_size) + base64 data
    if (s.size() < 20) return {};
    std::string hdr_hex = s.substr(4, 16);
    auto hdr = hex_decode(hdr_hex);
    if (hdr.size() < 8) return {};

    uint32_t decomp_size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                           ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    // uint32_t comp_size = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8) |
    //                      ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);

    std::string b64 = s.substr(20);
    auto compressed = base64_decode(b64);

    if (decomp_size == 0 || decomp_size > 1024 * 1024 * 128)
        return {};
    std::vector<uint8_t> result(decomp_size);
    if (!decompress_zlib(compressed.data(), compressed.size(),
                         result.data(), result.size()))
        result.clear();
    return result;
}

// ── VrSceneParser implementation ─────────────────────────────────────────

// forward declaration
static VrSceneValue parse_value(const std::string& val_str);

// Parse a balanced block enclosed in { }
// Returns the content between { } and the position after the closing }
static std::string extract_balanced(const std::string& text, size_t& pos) {
    if (pos >= text.size() || text[pos] != '{') return "";
    int depth = 0;
    size_t start = pos;
    for (size_t i = pos; i < text.size(); ++i) {
        if (text[i] == '{') {
            if (depth == 0) start = i;
            ++depth;
        } else if (text[i] == '}') {
            --depth;
            if (depth == 0) {
                std::string body = text.substr(start + 1, i - start - 1);
                pos = i + 1;
                return body;
            }
        }
    }
    pos = text.size();
    return {};
}

// Extract a balanced ( ) expression (for List, etc.)
static std::string extract_parens(const std::string& text, size_t& pos) {
    if (pos >= text.size() || text[pos] != '(') return "";
    int depth = 0;
    size_t start = pos;
    for (size_t i = pos; i < text.size(); ++i) {
        if (text[i] == '(') {
            if (depth == 0) start = i;
            ++depth;
        } else if (text[i] == ')') {
            --depth;
            if (depth == 0) {
                std::string inner = text.substr(start + 1, i - start - 1);
                pos = i + 1;
                return inner;
            }
        } else if (text[i] == '"') {
            // skip string
            ++i;
            while (i < text.size() && text[i] != '"') ++i;
        }
    }
    pos = text.size();
    return {};
}

VrSceneDocument VrSceneParser::parse(const std::string& text, ProgressFn progress) {
    VrSceneDocument doc;
    size_t pos = 0;
    size_t last_report = 0;
    double total = (double)text.size();

    while (pos < text.size()) {
        // progress
        if (progress && pos - last_report > 65536) {
            last_report = pos;
            progress(pos / total * 100.0);
        }
        // skip whitespace and comments
        while (pos < text.size()) {
            if (text[pos] == '/' && pos + 1 < text.size() && text[pos + 1] == '/') {
                // skip to end of line
                while (pos < text.size() && text[pos] != '\n') ++pos;
                continue;
            }
            if ((unsigned char)text[pos] <= ' ') { ++pos; continue; }
            break;
        }
        if (pos >= text.size()) break;

        // look for type name { pattern: a word followed by spaces then a word then {
        size_t save = pos;
        // read first word (plugin type)
        size_t start = pos;
        while (pos < text.size() && is_id_char(text[pos])) ++pos;
        if (pos == start) { ++pos; continue; }
        std::string type = text.substr(start, pos - start);

        // skip whitespace
        while (pos < text.size() && (unsigned char)text[pos] <= ' ') ++pos;

        // read second word (plugin name)
        start = pos;
        while (pos < text.size() && is_id_char(text[pos])) ++pos;
        if (pos == start) { ++pos; continue; }
        std::string name = text.substr(start, pos - start);

        // skip whitespace
        while (pos < text.size() && (unsigned char)text[pos] <= ' ') ++pos;

        // expect '{'
        if (pos >= text.size() || text[pos] != '{') {
            // not a plugin block, skip forward
            pos = save + 1;
            continue;
        }

        std::string body = extract_balanced(text, pos);
        if (body.empty()) continue;

        VrScenePlugin plugin;
        plugin.type = type;
        plugin.name = name;

        // Parse properties from body
        // First remove comments from body
        std::string cleaned;
        {
            std::istringstream stream(body);
            std::string line;
            while (std::getline(stream, line)) {
                cleaned += strip_comments(line) + "\n";
            }
        }

        // Find all key = value; assignments
        size_t bp = 0;
        while (bp < cleaned.size()) {
            // skip whitespace
            while (bp < cleaned.size() && (unsigned char)cleaned[bp] <= ' ') ++bp;
            if (bp >= cleaned.size() || !is_id_char(cleaned[bp])) {
                ++bp;
                continue;
            }

            // read key
            size_t ks = bp;
            while (bp < cleaned.size() && is_id_char(cleaned[bp])) ++bp;
            std::string key = cleaned.substr(ks, bp - ks);

            // skip whitespace and '='
            while (bp < cleaned.size() && (unsigned char)cleaned[bp] <= ' ') ++bp;
            if (bp >= cleaned.size() || cleaned[bp] != '=') continue;
            ++bp;
            while (bp < cleaned.size() && (unsigned char)cleaned[bp] <= ' ') ++bp;

            // read value until ';' at top level (handling balanced braces/parens/strings)
            size_t vs = bp;
            int paren_depth = 0;
            int brace_depth = 0;
            bool in_str = false;
            while (bp < cleaned.size()) {
                char c = cleaned[bp];
                if (in_str) {
                    if (c == '"') in_str = false;
                    ++bp;
                    continue;
                }
                if (c == '"') { in_str = true; ++bp; continue; }
                if (c == '(') { ++paren_depth; ++bp; continue; }
                if (c == ')') { --paren_depth; ++bp; continue; }
                if (c == '{') { ++brace_depth; ++bp; continue; }
                if (c == '}') { --brace_depth; ++bp; continue; }
                if (c == ';' && paren_depth == 0 && brace_depth == 0) break;
                ++bp;
            }

            std::string val_str = cleaned.substr(vs, bp - vs);
            if (bp < cleaned.size()) ++bp; // skip ';'

            val_str = trim(val_str);
            if (!val_str.empty() && val_str.back() == ';')
                val_str.pop_back();
            val_str = trim(val_str);

            if (!key.empty() && !val_str.empty())
                plugin.props[key] = parse_value(val_str);
        }

        doc.plugins.push_back(std::move(plugin));
    }

    return doc;
}

// ── value parsing ────────────────────────────────────────────────────────

static VrSceneValue parse_string(const std::string& s) {
    VrSceneValue v;
    v.type = VrSceneValue::STRING;
    v.str_val = s;
    return v;
}

static VrSceneValue parse_identifier(const std::string& s) {
    VrSceneValue v;
    v.type = VrSceneValue::IDENTIFIER;
    v.str_val = s;
    return v;
}

static VrSceneValue parse_number(const std::string& s) {
    VrSceneValue v;
    // check if float
    bool is_float = false;
    for (char c : s) {
        if (c == '.' || c == 'e' || c == 'E') { is_float = true; break; }
    }
    if (is_float) {
        v.type = VrSceneValue::FLOAT;
        v.float_val = std::stod(s);
    } else {
        v.type = VrSceneValue::INT;
        v.int_val = std::stoll(s);
    }
    return v;
}

static VrSceneValue parse_acolor(const std::string& s, size_t& pos) {
    // AColor(r,g,b,a) - skip '('
    VrSceneValue v;
    v.type = VrSceneValue::COLOR;
    // parse 4 comma-separated floats
    for (int i = 0; i < 3; ++i) {
        // skip whitespace
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        size_t ns = pos;
        while (pos < s.size() && s[pos] != ',' && s[pos] != ')') ++pos;
        if (i < 3)
            v.color_val[i] = std::stod(s.substr(ns, pos - ns));
        if (pos < s.size() && s[pos] == ',') ++pos;
    }
    // skip to ')'
    while (pos < s.size() && s[pos] != ')') ++pos;
    if (pos < s.size()) ++pos;
    return v;
}

static VrSceneValue parse_color(const std::string& s, size_t& pos) {
    // Color(r,g,b) - skip '('
    VrSceneValue v;
    v.type = VrSceneValue::COLOR;
    for (int i = 0; i < 3; ++i) {
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        size_t ns = pos;
        while (pos < s.size() && s[pos] != ',' && s[pos] != ')') ++pos;
        v.color_val[i] = std::stod(s.substr(ns, pos - ns));
        if (pos < s.size() && s[pos] == ',') ++pos;
    }
    while (pos < s.size() && s[pos] != ')') ++pos;
    if (pos < s.size()) ++pos;
    return v;
}

static VrSceneValue parse_vector(const std::string& s, size_t& pos) {
    // Vector(x, y, z)
    VrSceneValue v;
    v.type = VrSceneValue::VECTOR;
    for (int i = 0; i < 3; ++i) {
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        size_t ns = pos;
        while (pos < s.size() && s[pos] != ',' && s[pos] != ')') ++pos;
        v.vec_val[i] = std::stod(s.substr(ns, pos - ns));
        if (pos < s.size() && s[pos] == ',') ++pos;
    }
    while (pos < s.size() && s[pos] != ')') ++pos;
    if (pos < s.size()) ++pos;
    return v;
}

static VrSceneValue parse_transform(const std::string& s, size_t& pos) {
    // Transform(Matrix(Vector(...),Vector(...),Vector(...)),Vector(tx,ty,tz))
    VrSceneValue v;
    v.type = VrSceneValue::TRANSFORM;
    // initialize to identity
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            v.transform_val[r][c] = (r == c) ? 1.0 : 0.0;

    // Expect "Matrix("
    while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
    // read "Matrix"
    if (s.substr(pos, 6) == "Matrix") {
        pos += 6;
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos < s.size() && s[pos] == '(') ++pos;

        for (int row = 0; row < 3; ++row) {
            // expect "Vector("
            while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
            if (s.substr(pos, 6) == "Vector") {
                pos += 6;
                while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
                if (pos < s.size() && s[pos] == '(') ++pos;
                for (int col = 0; col < 3; ++col) {
                    while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
                    size_t ns = pos;
                    while (pos < s.size() && s[pos] != ',' && s[pos] != ')') ++pos;
                    v.transform_val[row][col] = std::stod(s.substr(ns, pos - ns));
                    if (pos < s.size() && s[pos] == ',') ++pos;
                }
                // skip ')'
                while (pos < s.size() && s[pos] != ')') ++pos;
                if (pos < s.size()) ++pos;
                // skip ',' between vectors
                while (pos < s.size() && ((unsigned char)s[pos] <= ' ' || s[pos] == ',')) ++pos;
            }
        }
        // skip ')' of Matrix
        while (pos < s.size() && s[pos] != ')') ++pos;
        if (pos < s.size()) ++pos;
    }

    // parse translation Vector
    while (pos < s.size() && ((unsigned char)s[pos] <= ' ' || s[pos] == ',')) ++pos;
    if (s.substr(pos, 6) == "Vector") {
        pos += 6;
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos < s.size() && s[pos] == '(') ++pos;
        for (int col = 0; col < 3; ++col) {
            while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
            size_t ns = pos;
            while (pos < s.size() && s[pos] != ',' && s[pos] != ')') ++pos;
            v.transform_val[3][col] = std::stod(s.substr(ns, pos - ns));
            if (pos < s.size() && s[pos] == ',') ++pos;
        }
    }

    return v;
}

static VrSceneValue parse_transform_hex(const std::string& s, size_t& pos) {
    // TransformHex("hex64") - 64 hex chars = 32 bytes = 16 floats
    VrSceneValue v;
    v.type = VrSceneValue::TRANSFORM;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            v.transform_val[r][c] = (r == c) ? 1.0 : 0.0;

    while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
    if (pos < s.size() && s[pos] == '"') ++pos;
    size_t hs = pos;
    while (pos < s.size() && s[pos] != '"') ++pos;

    std::string hex = s.substr(hs, pos - hs);
    auto bytes = hex_decode(hex);
    if (bytes.size() >= 64) {
        for (int r = 0; r < 4; ++r)
            for (int c = 0; c < 4; ++c) {
                uint32_t bits = (uint32_t)bytes[(r * 4 + c) * 4] |
                               ((uint32_t)bytes[(r * 4 + c) * 4 + 1] << 8) |
                               ((uint32_t)bytes[(r * 4 + c) * 4 + 2] << 16) |
                               ((uint32_t)bytes[(r * 4 + c) * 4 + 3] << 24);
                float f;
                memcpy(&f, &bits, sizeof(f));
                v.transform_val[r][c] = f;
            }
    }

    if (pos < s.size()) ++pos; // skip closing "
    // skip to closing )
    while (pos < s.size() && s[pos] != ')') ++pos;
    if (pos < s.size()) ++pos;
    return v;
}

static VrSceneValue parse_list_int_hex(const std::string& inner) {
    // inner is the string content (without outer quotes)
    std::string s = trim(inner);
    if (s.empty()) return VrSceneValue();

    VrSceneValue v;
    if (s.size() >= 4 && s.substr(0, 4) == "ZIPB") {
        auto raw = zipb_decode(s);
        v.type = VrSceneValue::BINARY_I32;
        if (raw.size() >= 4) {
            v.bin_i32.resize(raw.size() / 4);
            memcpy(v.bin_i32.data(), raw.data(), raw.size() & ~3);
        }
    } else if (s.size() >= 4 && s.substr(0, 4) == "ZIPC") {
        auto raw = zipc_decode(s);
        v.type = VrSceneValue::BINARY_I32;
        if (raw.size() >= 4) {
            v.bin_i32.resize(raw.size() / 4);
            memcpy(v.bin_i32.data(), raw.data(), raw.size() & ~3);
        }
    } else {
        // plain hex
        auto raw = hex_decode(s);
        v.type = VrSceneValue::BINARY_I32;
        if (raw.size() >= 4) {
            v.bin_i32.resize(raw.size() / 4);
            memcpy(v.bin_i32.data(), raw.data(), raw.size() & ~3);
        }
    }
    return v;
}

static VrSceneValue parse_list_vector_hex(const std::string& inner) {
    std::string s = trim(inner);
    if (s.empty()) return VrSceneValue();

    VrSceneValue v;
    if (s.size() >= 4 && s.substr(0, 4) == "ZIPB") {
        auto raw = zipb_decode(s);
        v.type = VrSceneValue::BINARY_F32;
        if (raw.size() >= 4) {
            v.bin_f32.resize(raw.size() / 4);
            memcpy(v.bin_f32.data(), raw.data(), raw.size() & ~3);
        }
    } else if (s.size() >= 4 && s.substr(0, 4) == "ZIPC") {
        auto raw = zipc_decode(s);
        v.type = VrSceneValue::BINARY_F32;
        if (raw.size() >= 4) {
            v.bin_f32.resize(raw.size() / 4);
            memcpy(v.bin_f32.data(), raw.data(), raw.size() & ~3);
        }
    } else {
        auto raw = hex_decode(s);
        v.type = VrSceneValue::BINARY_F32;
        if (raw.size() >= 4) {
            v.bin_f32.resize(raw.size() / 4);
            memcpy(v.bin_f32.data(), raw.data(), raw.size() & ~3);
        }
    }
    return v;
}

static VrSceneValue parse_list(const std::string& inner) {
    VrSceneValue v;
    v.type = VrSceneValue::LIST;

    std::string s = trim(inner);
    if (s.empty()) return v;

    // Split by top-level commas
    size_t pos = 0;
    while (pos < s.size()) {
        // skip whitespace
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos >= s.size()) break;

        size_t start = pos;
        int paren_depth = 0;
        int brace_depth = 0;
        bool in_str = false;
        while (pos < s.size()) {
            char c = s[pos];
            if (in_str) {
                if (c == '"') in_str = false;
                ++pos;
                continue;
            }
            if (c == '"') { in_str = true; ++pos; continue; }
            if (c == '(') { ++paren_depth; ++pos; continue; }
            if (c == ')') { --paren_depth; ++pos; continue; }
            if (c == '{') { ++brace_depth; ++pos; continue; }
            if (c == '}') { --brace_depth; ++pos; continue; }
            if (c == ',' && paren_depth == 0 && brace_depth == 0) {
                ++pos;
                break;
            }
            ++pos;
        }

        std::string item = s.substr(start, pos - start);
        item = trim(item);
        if (!item.empty())
            v.list_val.push_back(parse_value(item));
    }

    return v;
}

static VrSceneValue parse_list_string(const std::string& inner) {
    VrSceneValue v;
    v.type = VrSceneValue::LIST_STRING;

    std::string s = trim(inner);
    size_t pos = 0;
    while (pos < s.size()) {
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos >= s.size()) break;
        if (s[pos] == '"') {
            ++pos;
            size_t ss = pos;
            while (pos < s.size() && s[pos] != '"') ++pos;
            v.list_str.push_back(s.substr(ss, pos - ss));
            if (pos < s.size()) ++pos; // skip closing "
        }
        // skip comma
        while (pos < s.size() && s[pos] != ',' && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos < s.size() && s[pos] == ',') ++pos;
    }

    return v;
}

static VrSceneValue parse_value(const std::string& val_str) {
    std::string s = trim(val_str);
    if (s.empty()) {
        VrSceneValue v;
        v.type = VrSceneValue::NONE;
        return v;
    }

    // String
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        return parse_string(s.substr(1, s.size() - 2));

    // ListString
    if (s.size() >= 11 && s.substr(0, 10) == "ListString" && s.back() == ')') {
        size_t pos = 10;
        // skip '('
        while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
        if (pos < s.size() && s[pos] == '(') {
            ++pos;
            std::string inner;
            int pd = 1;
            while (pos < s.size() && pd > 0) {
                if (s[pos] == '(') ++pd;
                else if (s[pos] == ')') --pd;
                if (pd > 0) inner += s[pos];
                ++pos;
            }
            return parse_list_string(inner);
        }
    }

    // AColor(r,g,b,a) or Color(r,g,b)
    if (s.size() >= 7 && s.substr(0, 6) == "AColor" && s.back() == ')') {
        size_t pos = 7;
        return parse_acolor(s, pos);
    }
    if (s.size() >= 6 && s.substr(0, 5) == "Color" && s.back() == ')') {
        size_t pos = 6;
        return parse_color(s, pos);
    }

    // Vector(x,y,z)
    if (s.size() >= 7 && s.substr(0, 6) == "Vector" && s.back() == ')') {
        size_t pos = 7;
        return parse_vector(s, pos);
    }

    // Transform(Matrix(Vector(...),Vector(...),Vector(...)),Vector(tx,ty,tz))
    if (s.size() >= 10 && s.substr(0, 9) == "Transform" && s.back() == ')') {
        // Check if TransformHex
        if (s.size() >= 13 && s.substr(0, 12) == "TransformHex") {
            size_t pos = 13;
            return parse_transform_hex(s, pos);
        }
        size_t pos = 10;
        return parse_transform(s, pos);
    }
    // TransformHex
    if (s.size() >= 13 && s.substr(0, 12) == "TransformHex" && s.back() == ')') {
        size_t pos = 13;
        return parse_transform_hex(s, pos);
    }

    // ListIntHex("...")
    if (s.size() >= 12 && s.substr(0, 11) == "ListIntHex(" && s.back() == ')') {
        std::string inner = s.substr(11, s.size() - 12);
        inner = trim(inner);
        if (inner.size() >= 2 && inner.front() == '"' && inner.back() == '"')
            inner = inner.substr(1, inner.size() - 2);
        return parse_list_int_hex(inner);
    }

    // ListVectorHex("...")
    if (s.size() >= 15 && s.substr(0, 14) == "ListVectorHex(" && s.back() == ')') {
        std::string inner = s.substr(14, s.size() - 15);
        inner = trim(inner);
        if (inner.size() >= 2 && inner.front() == '"' && inner.back() == '"')
            inner = inner.substr(1, inner.size() - 2);
        return parse_list_vector_hex(inner);
    }

    // List(...)
    if (s.size() >= 5 && s.substr(0, 4) == "List" && s.back() == ')') {
        // Make sure it's not ListIntHex, ListVectorHex, ListString
        if (s.substr(0, 11) != "ListIntHex(" &&
            s.substr(0, 14) != "ListVectorHex(" &&
            s.substr(0, 10) != "ListString(" &&
            s.size() > 5) {
            size_t pos = 5;
            // skip '('
            while (pos < s.size() && (unsigned char)s[pos] <= ' ') ++pos;
            std::string inner;
            if (pos < s.size() && s[pos] == '(') {
                ++pos;
                int pd = 1;
                while (pos < s.size() && pd > 0) {
                    char c = s[pos];
                    if (c == '"') {
                        inner += c;
                        ++pos;
                        while (pos < s.size() && s[pos] != '"') inner += s[pos++];
                        if (pos < s.size()) inner += s[pos++];
                        continue;
                    }
                    if (c == '(') ++pd;
                    else if (c == ')') --pd;
                    if (pd > 0) inner += c;
                    ++pos;
                }
            }
            return parse_list(inner);
        }
        // List() empty
        VrSceneValue v;
        v.type = VrSceneValue::LIST;
        return v;
    }

    // Number
    {
        bool is_num = true;
        bool has_dot_or_e = false;
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c == '-' && i == 0) continue;
            if (c == '.' || c == 'e' || c == 'E') { has_dot_or_e = true; continue; }
            if (!std::isdigit((unsigned char)c)) { is_num = false; break; }
        }
        if (is_num && !s.empty())
            return parse_number(s);
    }

    // Identifier (plugin reference)
    {
        bool is_id = !s.empty();
        for (char c : s) {
            if (!is_id_char(c)) { is_id = false; break; }
        }
        if (is_id)
            return parse_identifier(s);
    }

    // fallback: treat as string/identifier
    return parse_identifier(s);
}

// ── JSON writer ──────────────────────────────────────────────────────────

std::string JsonWriter::indent_str(int indent) {
    return std::string((size_t)indent * 2, ' ');
}

std::string JsonWriter::escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

std::string JsonWriter::write(const VrSceneValue& val, int indent, bool uncompressed) {
    switch (val.type) {
        case VrSceneValue::NONE:
            return "null";
        case VrSceneValue::STRING:
            return "\"" + escape_json(val.str_val) + "\"";
        case VrSceneValue::INT:
            return std::to_string(val.int_val);
        case VrSceneValue::FLOAT: {
            char buf[64];
            snprintf(buf, sizeof(buf), "%.17g", val.float_val);
            std::string s(buf);
            if (s.find('.') == std::string::npos && s.find('e') == std::string::npos && s.find('E') == std::string::npos)
                s += ".0";
            return s;
        }
        case VrSceneValue::COLOR:
            return "[" + std::to_string(val.color_val[0]) + ", " +
                   std::to_string(val.color_val[1]) + ", " +
                   std::to_string(val.color_val[2]) + "]";
        case VrSceneValue::VECTOR:
            return "[" + std::to_string(val.vec_val[0]) + ", " +
                   std::to_string(val.vec_val[1]) + ", " +
                   std::to_string(val.vec_val[2]) + "]";
        case VrSceneValue::TRANSFORM: {
            std::string out = "[\n";
            for (int r = 0; r < 4; ++r) {
                out += indent_str(indent + 1) + "[";
                for (int c = 0; c < 4; ++c) {
                    if (c > 0) out += ", ";
                    char buf[64];
                    snprintf(buf, sizeof(buf), "%.17g", val.transform_val[r][c]);
                    out += buf;
                }
                out += "]";
                if (r < 3) out += ",";
                out += "\n";
            }
            out += indent_str(indent) + "]";
            return out;
        }
        case VrSceneValue::BINARY_I32: {
            if (!uncompressed) {
                std::string b64 = base64_encode(val.bin_i32.data(),
                    val.bin_i32.size() * sizeof(int32_t));
                return "{\"enc\":\"base64\",\"type\":\"int32\",\"count\":" +
                    std::to_string(val.bin_i32.size()) + ",\"data\":\"" + b64 + "\"}";
            }
            std::string out = "[";
            for (size_t i = 0; i < val.bin_i32.size(); ++i) {
                if (i > 0) out += ", ";
                out += std::to_string(val.bin_i32[i]);
            }
            out += "]";
            return out;
        }
        case VrSceneValue::BINARY_F32: {
            if (!uncompressed) {
                std::string b64 = base64_encode(val.bin_f32.data(),
                    val.bin_f32.size() * sizeof(float));
                return "{\"enc\":\"base64\",\"type\":\"float32\",\"count\":" +
                    std::to_string(val.bin_f32.size()) + ",\"data\":\"" + b64 + "\"}";
            }
            std::string out = "[";
            for (size_t i = 0; i < val.bin_f32.size(); ++i) {
                if (i > 0) out += ", ";
                char buf[64];
                snprintf(buf, sizeof(buf), "%.8g", val.bin_f32[i]);
                out += buf;
            }
            out += "]";
            return out;
        }
        case VrSceneValue::LIST: {
            if (val.list_val.empty()) return "[]";
            std::string out = "[\n";
            for (size_t i = 0; i < val.list_val.size(); ++i) {
                out += indent_str(indent + 1) + write(val.list_val[i], indent + 1, uncompressed);
                if (i + 1 < val.list_val.size()) out += ",";
                out += "\n";
            }
            out += indent_str(indent) + "]";
            return out;
        }
        case VrSceneValue::IDENTIFIER:
            return "\"" + escape_json(val.str_val) + "\"";
        case VrSceneValue::LIST_STRING: {
            if (val.list_str.empty()) return "[]";
            std::string out = "[\n";
            for (size_t i = 0; i < val.list_str.size(); ++i) {
                out += indent_str(indent + 1) + "\"" + escape_json(val.list_str[i]) + "\"";
                if (i + 1 < val.list_str.size()) out += ",";
                out += "\n";
            }
            out += indent_str(indent) + "]";
            return out;
        }
    }
    return "null";
}

std::string JsonWriter::write(const VrSceneDocument& doc, int indent, bool uncompressed) {
    std::string out = "{\n";
    out += indent_str(indent + 1) + "\"plugins\": [\n";
    for (size_t i = 0; i < doc.plugins.size(); ++i) {
        const auto& p = doc.plugins[i];
        out += indent_str(indent + 2) + "{\n";
        out += indent_str(indent + 3) + "\"type\": \"" + escape_json(p.type) + "\",\n";
        out += indent_str(indent + 3) + "\"name\": \"" + escape_json(p.name) + "\",\n";
        out += indent_str(indent + 3) + "\"props\": {\n";

        size_t pi = 0;
        for (const auto& kv : p.props) {
            out += indent_str(indent + 4) + "\"" + escape_json(kv.first) + "\": " + write(kv.second, indent + 4, uncompressed);
            ++pi;
            if (pi < p.props.size()) out += ",";
            out += "\n";
        }

        out += indent_str(indent + 3) + "}\n";
        out += indent_str(indent + 2) + "}";
        if (i + 1 < doc.plugins.size()) out += ",";
        out += "\n";
    }
    out += indent_str(indent + 1) + "]\n";
    out += "}\n";
    return out;
}
