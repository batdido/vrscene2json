#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

struct VrSceneValue {
    enum Type {
        NONE,
        STRING,
        INT,
        FLOAT,
        COLOR,
        VECTOR,
        TRANSFORM,
        BINARY_I32,
        BINARY_F32,
        LIST,
        IDENTIFIER,
        LIST_STRING,
    };
    Type type;
    std::string str_val;
    int64_t int_val;
    double float_val;
    double color_val[3];
    double vec_val[3];
    double transform_val[4][4];  // row-major 4x4
    std::vector<int32_t> bin_i32;
    std::vector<float> bin_f32;
    std::vector<VrSceneValue> list_val;
    std::vector<std::string> list_str;
};

struct VrScenePlugin {
    std::string type;
    std::string name;
    std::unordered_map<std::string, VrSceneValue> props;
};

struct VrSceneDocument {
    std::vector<VrScenePlugin> plugins;
};

using ProgressFn = void(*)(double pct);

struct VrSceneParser {
    static VrSceneDocument parse(const std::string& text, ProgressFn progress = nullptr);
};

struct JsonWriter {
    static std::string write(const VrSceneValue& val, int indent = 0);
    static std::string write(const VrSceneDocument& doc, int indent = 0);
    static std::string indent_str(int indent);
    static std::string escape_json(const std::string& s);
};
