#include "VrSceneParser.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <windows.h>

struct Timer {
    LARGE_INTEGER start_, freq_;
    Timer() { QueryPerformanceFrequency(&freq_); QueryPerformanceCounter(&start_); }
    void reset() { QueryPerformanceCounter(&start_); }
    double elapsed_ms() const {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        return (double)(now.QuadPart - start_.QuadPart) / freq_.QuadPart * 1000.0;
    }
};

static void progress_fn(double pct) {
    static int last = -1;
    int cur = (int)pct;
    if (cur != last && cur % 5 == 0) {
        std::cerr << "\rParsing... " << cur << "%   " << std::flush;
        last = cur;
    }
}

int main(int argc, char** argv) {
    bool uncompressed = false;
    const char* in_path = nullptr;
    const char* out_path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--uncompressed") == 0)
            uncompressed = true;
        else if (!in_path)
            in_path = argv[i];
        else if (!out_path)
            out_path = argv[i];
    }

    if (!in_path) {
        std::cerr << "Usage: vrscene2json [-u|--uncompressed] input.vrscene [output.json]\n";
        return 1;
    }

    Timer read_timer;
    std::ifstream in(in_path, std::ios::binary);
    if (!in) {
        std::cerr << "Error: cannot open " << in_path << "\n";
        return 1;
    }
    std::string text((std::istreambuf_iterator<char>(in)),
                      std::istreambuf_iterator<char>());
    in.close();
    double read_ms = read_timer.elapsed_ms();

    // normalize line endings
    for (auto& c : text)
        if (c == '\r') c = '\n';

    try {
        std::cerr << "File: " << in_path << " (" << text.size() << " bytes)\n"
                  << "Read:  " << read_ms << " ms\n"
                  << "Mode:  " << (uncompressed ? "uncompressed" : "encoded") << "\n";

        Timer parse_timer;
        VrSceneDocument doc = VrSceneParser::parse(text, progress_fn);
        double parse_ms = parse_timer.elapsed_ms();

        std::cerr << "\rParsing... 100%   \n"
                  << "Parse: " << parse_ms << " ms, "
                  << doc.plugins.size() << " plugins\n";

        Timer write_timer;
        std::string json = JsonWriter::write(doc, 0, uncompressed);
        double json_ms = write_timer.elapsed_ms();

        std::cerr << "Json:  " << json_ms << " ms (" << json.size() << " bytes)\n";

        Timer file_timer;
        if (out_path) {
            std::ofstream out(out_path);
            out << json;
        } else {
            std::cout << json;
        }
        double file_ms = file_timer.elapsed_ms();
        std::cerr << "File:  " << file_ms << " ms\n";

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
