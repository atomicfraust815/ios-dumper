#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace iosdumper {
struct Signature {
    std::string name;
    std::string pattern;
    std::string kind = "match";
    int dispOffset = 0;
    int instructionSize = 0;
    bool required = true;
};

struct DumperConfig {
    int schema = 0;
    std::wstring module;
    std::vector<Signature> signatures;
};

std::vector<int> ParsePattern(std::string_view pattern);
bool ParseConfig(std::string_view text, DumperConfig& config, std::string& error);
bool LoadConfig(const std::filesystem::path& path, DumperConfig& config, std::string& error);
} // namespace iosdumper
