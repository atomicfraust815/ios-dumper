#include "config.hpp"
#include "json.hpp"

#include <cmath>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <utility>

namespace iosdumper {
namespace {
constexpr std::size_t kMaximumConfigSize = 1024u * 1024u;

int HexDigit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool JsonInteger(const Json::Value* value, int& output) {
    if (!value || value->type != Json::Type::Number ||
        std::floor(value->number) != value->number ||
        value->number < (std::numeric_limits<int>::min)() ||
        value->number > (std::numeric_limits<int>::max)()) return false;
    output = static_cast<int>(value->number);
    return true;
}
} // namespace

std::vector<int> ParsePattern(std::string_view pattern) {
    std::vector<int> bytes;
    std::size_t position = 0;
    while (position < pattern.size()) {
        while (position < pattern.size() &&
               std::isspace(static_cast<unsigned char>(pattern[position]))) ++position;
        if (position == pattern.size()) break;
        const std::size_t tokenStart = position;
        while (position < pattern.size() &&
               !std::isspace(static_cast<unsigned char>(pattern[position]))) ++position;
        const std::string_view token = pattern.substr(tokenStart, position - tokenStart);
        if (token == "?" || token == "??") {
            bytes.push_back(-1);
            continue;
        }
        if (token.size() != 2) return {};
        const int high = HexDigit(token[0]);
        const int low = HexDigit(token[1]);
        if (high < 0 || low < 0) return {};
        bytes.push_back((high << 4) | low);
    }
    return bytes;
}

bool ParseConfig(std::string_view text, DumperConfig& config, std::string& error) {
    if (text.size() > kMaximumConfigSize) {
        error = "configuration exceeds 1 MiB";
        return false;
    }
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) text.remove_prefix(3);

    Json::Value root;
    Json::Parser parser(text);
    if (!parser.Parse(root, error)) return false;
    if (root.type != Json::Type::Object) {
        error = "configuration root must be an object";
        return false;
    }

    int schema = 0;
    if (!JsonInteger(root.Find("schema"), schema) || schema != 1) {
        error = "schema must be integer 1";
        return false;
    }
    const Json::Value* module = root.Find("module");
    const Json::Value* signatures = root.Find("signatures");
    if (!module || module->type != Json::Type::String || module->string.empty()) {
        error = "module must be a non-empty string";
        return false;
    }
    if (!signatures || signatures->type != Json::Type::Array || signatures->array.empty()) {
        error = "signatures must be a non-empty array";
        return false;
    }

    DumperConfig parsed;
    parsed.schema = schema;
    for (const unsigned char character : module->string) {
        if (character == 0 || character > 0x7F) {
            error = "module must contain an ASCII Windows module name";
            return false;
        }
        parsed.module.push_back(static_cast<wchar_t>(character));
    }
    std::set<std::string> names;
    for (std::size_t index = 0; index < signatures->array.size(); ++index) {
        const Json::Value& item = signatures->array[index];
        if (item.type != Json::Type::Object) {
            error = "signature #" + std::to_string(index) + " must be an object";
            return false;
        }
        const Json::Value* name = item.Find("name");
        const Json::Value* pattern = item.Find("pattern");
        const Json::Value* kind = item.Find("kind");
        const Json::Value* required = item.Find("required");
        if (!name || name->type != Json::Type::String || name->string.empty() ||
            !pattern || pattern->type != Json::Type::String || pattern->string.empty() ||
            !kind || kind->type != Json::Type::String || kind->string.empty()) {
            error = "signature #" + std::to_string(index) +
                " requires non-empty name, pattern and kind strings";
            return false;
        }
        if (!names.insert(name->string).second) {
            error = "duplicate signature name: " + name->string;
            return false;
        }
        Signature signature;
        signature.name = name->string;
        signature.pattern = pattern->string;
        signature.kind = kind->string;
        if (required) {
            if (required->type != Json::Type::Boolean) {
                error = "required must be boolean for " + signature.name;
                return false;
            }
            signature.required = required->boolean;
        }
        const std::vector<int> parsedPattern = ParsePattern(signature.pattern);
        if (parsedPattern.empty()) {
            error = "invalid byte pattern for " + signature.name;
            return false;
        }
        if (signature.kind == "rip_rel32") {
            if (!JsonInteger(item.Find("disp_offset"), signature.dispOffset) ||
                !JsonInteger(item.Find("instruction_size"), signature.instructionSize) ||
                signature.dispOffset < 0 || signature.instructionSize <= 0 ||
                signature.dispOffset + static_cast<int>(sizeof(std::int32_t)) > signature.instructionSize ||
                static_cast<std::size_t>(signature.instructionSize) > parsedPattern.size()) {
                error = "invalid RIP-relative offsets for " + signature.name;
                return false;
            }
        } else if (signature.kind != "match") {
            error = "unknown signature kind for " + signature.name + ": " + signature.kind;
            return false;
        }
        parsed.signatures.push_back(std::move(signature));
    }
    config = std::move(parsed);
    error.clear();
    return true;
}

bool LoadConfig(const std::filesystem::path& path, DumperConfig& config, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "could not open " + path.string();
        return false;
    }
    const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return ParseConfig(text, config, error);
}
} // namespace iosdumper
