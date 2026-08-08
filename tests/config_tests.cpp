#include "config.hpp"

#include <iostream>
#include <string>

namespace {
int failures = 0;

void Check(bool condition, const char* message) {
    if (condition) return;
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
}

bool Parse(std::string text, iosdumper::DumperConfig& config, std::string& error) {
    return iosdumper::ParseConfig(text, config, error);
}

void ExpectInvalid(const std::string& text, const char* message) {
    iosdumper::DumperConfig config;
    std::string error;
    Check(!Parse(text, config, error), message);
    Check(!error.empty(), "invalid configuration should explain the failure");
}
} // namespace

int main() {
    const auto pattern = iosdumper::ParsePattern("48 8B 0D ? ?? 7f");
    Check(pattern.size() == 6, "pattern token count");
    Check(pattern.size() == 6 && pattern[0] == 0x48 && pattern[3] == -1 &&
          pattern[4] == -1 && pattern[5] == 0x7F, "pattern byte values");
    Check(iosdumper::ParsePattern("4 8B").empty(), "reject short hex token");
    Check(iosdumper::ParsePattern("GG").empty(), "reject non-hex token");

    const std::string valid = R"json({
      "schema": 1,
      "module": "client.dll",
      "signatures": [
        {"name":"direct","pattern":"48 89 5C 24 ?","kind":"match"},
        {"name":"relative","pattern":"48 8B 0D ? ? ? ?","kind":"rip_rel32",
         "required":false,"disp_offset":3,"instruction_size":7}
      ]
    })json";
    iosdumper::DumperConfig config;
    std::string error;
    Check(Parse(valid, config, error), "accept valid configuration");
    Check(config.schema == 1 && config.module == L"client.dll", "read root fields");
    Check(config.signatures.size() == 2, "read signatures");
    Check(config.signatures.size() == 2 && config.signatures[0].required,
          "required defaults to true");
    Check(config.signatures.size() == 2 && !config.signatures[1].required &&
          config.signatures[1].dispOffset == 3, "read RIP-relative fields");

    iosdumper::DumperConfig bomConfig;
    std::string bomError;
    Check(Parse(std::string("\xEF\xBB\xBF") + valid, bomConfig, bomError),
          "accept UTF-8 BOM");

    ExpectInvalid(R"({"schema":1,"schema":1,"module":"client.dll","signatures":[]})",
                  "reject duplicate JSON keys");
    ExpectInvalid(R"({"schema":2,"module":"client.dll","signatures":[{"name":"x","pattern":"AA","kind":"match"}]})",
                  "reject unsupported schema");
    ExpectInvalid(R"({"schema":1,"module":"client.dll","signatures":[{"name":"x","pattern":"AA","kind":"match"},{"name":"x","pattern":"BB","kind":"match"}]})",
                  "reject duplicate signature names");
    ExpectInvalid(R"({"schema":1,"module":"client.dll","signatures":[{"name":"x","pattern":"AA","kind":"unknown"}]})",
                  "reject unknown signature kind");
    ExpectInvalid(R"({"schema":1,"module":"client.dll","signatures":[{"name":"x","pattern":"48 8B 0D ? ? ? ?","kind":"rip_rel32","disp_offset":5,"instruction_size":7}]})",
                  "reject displacement outside instruction");
    ExpectInvalid(valid + " trailing", "reject trailing content");

    if (failures) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All configuration tests passed\n";
    return 0;
}
