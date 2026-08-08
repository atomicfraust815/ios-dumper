#include <Windows.h>
#include <TlHelp32.h>
#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace {
using iosdumper::DumperConfig;
using iosdumper::LoadConfig;
using iosdumper::ParsePattern;
using iosdumper::Signature;

struct Module {
    std::wstring name;
    std::uintptr_t base = 0;
    std::size_t size = 0;

    bool contains(std::uintptr_t address, std::size_t length = 1) const {
        if (!base || !size || !address || !length || address < base) return false;
        const std::uintptr_t offset = address - base;
        return offset < size && length <= size - static_cast<std::size_t>(offset);
    }
};

struct SignatureResult {
    std::string name;
    bool required = true;
    bool found = false;
    std::size_t matchCount = 0;
    std::uintptr_t value = 0;
    std::string error;
};

struct InterfaceFactory {
    std::uintptr_t createFn = 0;
    std::string version;
};

struct RemoteRecvProp {
    std::uint64_t name;
    std::int32_t type;
    std::int32_t flags;
    std::int32_t stringBufferSize;
    std::uint8_t insideArray;
    std::uint8_t padding[3];
    std::uint64_t extraData;
    std::uint64_t arrayProp;
    std::uint64_t arrayLengthProxy;
    std::uint64_t proxy;
    std::uint64_t dataTableProxy;
    std::uint64_t dataTable;
    std::int32_t offset;
    std::int32_t elementStride;
    std::int32_t elementCount;
    std::uint32_t padding2;
    std::uint64_t parentArrayPropName;
};

struct RemoteRecvTable {
    std::uint64_t props;
    std::int32_t propCount;
    std::uint32_t padding;
    std::uint64_t decoder;
    std::uint64_t name;
};

struct RemoteClientClass {
    std::uint64_t createFn;
    std::uint64_t createEventFn;
    std::uint64_t networkName;
    std::uint64_t recvTable;
    std::uint64_t next;
    std::int32_t classId;
    std::uint32_t padding;
};

struct RemoteInterfaceReg {
    std::uint64_t createFn;
    std::uint64_t name;
    std::uint64_t next;
};

static_assert(sizeof(RemoteRecvProp) == 96, "RecvProp x64 layout changed");
static_assert(sizeof(RemoteRecvTable) == 32, "RecvTable x64 layout changed");
static_assert(sizeof(RemoteClientClass) == 48, "ClientClass x64 layout changed");
static_assert(sizeof(RemoteInterfaceReg) == 24, "InterfaceReg x64 layout changed");

class Process {
public:
    explicit Process(DWORD pid) : handle_(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)) {}
    ~Process() { if (handle_) CloseHandle(handle_); }
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    bool valid() const { return handle_ != nullptr; }

    template <typename T>
    bool read(std::uintptr_t address, T& out) const { return readBytes(address, &out, sizeof(out)); }

    bool readBytes(std::uintptr_t address, void* out, std::size_t length) const {
        SIZE_T received = 0;
        return handle_ && ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), out,
            length, &received) && received == length;
    }

    bool query(std::uintptr_t address, MEMORY_BASIC_INFORMATION& output) const {
        return handle_ && VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(address),
            &output, sizeof(output)) == sizeof(output);
    }

    static bool readable(const MEMORY_BASIC_INFORMATION& info) {
        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        switch (info.Protect & 0xFFu) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    std::string readString(std::uintptr_t address, std::size_t maxLength = 256) const {
        if (!address || maxLength == 0 || maxLength > 4096) return {};
        std::string value;
        value.reserve(maxLength);
        while (value.size() < maxLength) {
            MEMORY_BASIC_INFORMATION info = {};
            if (!query(address, info) || !readable(info)) return {};
            const std::uintptr_t regionEnd = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
            if (regionEnd <= address) return {};
            const std::size_t available = static_cast<std::size_t>(regionEnd - address);
            const std::size_t chunkSize = (std::min)(available, maxLength - value.size());
            std::vector<char> chunk(chunkSize);
            if (!readBytes(address, chunk.data(), chunk.size())) return {};
            const auto terminator = std::find(chunk.begin(), chunk.end(), '\0');
            value.append(chunk.begin(), terminator);
            if (terminator != chunk.end()) return value;
            address += chunkSize;
        }
        return {};
    }

private:
    HANDLE handle_ = nullptr;
};

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return value;
}

std::optional<DWORD> FindProcessId(const std::wstring& imageName) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;
    PROCESSENTRY32W entry = { sizeof(entry) };
    const std::wstring expected = Lower(imageName);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
        if (Lower(entry.szExeFile) == expected) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    }
    CloseHandle(snapshot);
    return std::nullopt;
}

std::optional<Module> FindModule(DWORD pid, const std::wstring& requestedName) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;
    MODULEENTRY32W entry = { sizeof(entry) };
    const std::wstring expected = Lower(requestedName);
    for (BOOL ok = Module32FirstW(snapshot, &entry); ok; ok = Module32NextW(snapshot, &entry)) {
        if (Lower(entry.szModule) == expected) {
            Module module = { entry.szModule, reinterpret_cast<std::uintptr_t>(entry.modBaseAddr), entry.modBaseSize };
            CloseHandle(snapshot);
            return module;
        }
    }
    CloseHandle(snapshot);
    return std::nullopt;
}

void ScanBuffer(const unsigned char* data, std::size_t size, std::uintptr_t remoteBase,
                const std::vector<int>& pattern, std::vector<std::uintptr_t>& matches) {
    if (!data || pattern.empty() || pattern.size() > size) return;
    const std::size_t end = size - pattern.size();
    for (std::size_t i = 0; i <= end; ++i) {
        bool matched = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] >= 0 && data[i + j] != static_cast<unsigned char>(pattern[j])) {
                matched = false;
                break;
            }
        }
        if (matched) matches.push_back(remoteBase + i);
    }
}

std::vector<std::uintptr_t> ScanModule(const Process& process, const Module& module,
                                       const std::vector<int>& pattern) {
    std::vector<std::uintptr_t> matches;
    if (pattern.empty() || pattern.size() > module.size || module.size > 512u * 1024u * 1024u)
        return matches;

    constexpr std::size_t kChunkSize = 1024u * 1024u;
    std::uintptr_t cursor = module.base;
    const std::uintptr_t moduleEnd = module.base + module.size;
    while (cursor < moduleEnd) {
        MEMORY_BASIC_INFORMATION info = {};
        if (!process.query(cursor, info)) break;
        const std::uintptr_t regionBase = (std::max)(cursor,
            reinterpret_cast<std::uintptr_t>(info.BaseAddress));
        const std::uintptr_t rawRegionEnd = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
        const std::uintptr_t regionEnd = (std::min)(moduleEnd, rawRegionEnd);
        if (regionEnd <= cursor) break;

        if (Process::readable(info)) {
            std::uintptr_t chunkBase = regionBase;
            while (chunkBase < regionEnd) {
                const std::size_t remaining = static_cast<std::size_t>(regionEnd - chunkBase);
                const std::size_t payload = (std::min)(remaining, kChunkSize);
                const std::size_t overlap = (chunkBase + payload < regionEnd && pattern.size() > 1)
                    ? (std::min)(pattern.size() - 1, remaining - payload) : 0;
                std::vector<unsigned char> chunk(payload + overlap);
                if (process.readBytes(chunkBase, chunk.data(), chunk.size()))
                    ScanBuffer(chunk.data(), chunk.size(), chunkBase, pattern, matches);
                chunkBase += payload;
            }
        }
        cursor = regionEnd;
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches;
}

bool ReadNtHeaders(const Process& process, const Module& module, IMAGE_NT_HEADERS64& nt) {
    IMAGE_DOS_HEADER dos = {};
    if (!module.contains(module.base, sizeof(dos)) || !process.read(module.base, dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) return false;
    const auto ntAddress = module.base + static_cast<std::uint32_t>(dos.e_lfanew);
    if (!module.contains(ntAddress, sizeof(nt)) || !process.read(ntAddress, nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage == 0 || nt.OptionalHeader.SizeOfImage > module.size) return false;
    return true;
}

std::optional<std::uintptr_t> AddressFromRva(const Module& module, DWORD rva,
                                             std::size_t length = 1) {
    if (!rva || rva >= module.size) return std::nullopt;
    const std::uintptr_t address = module.base + rva;
    if (!module.contains(address, length)) return std::nullopt;
    return address;
}

std::optional<std::uintptr_t> ExportAddress(const Process& process, const Module& module, const char* exportName) {
    IMAGE_NT_HEADERS64 nt = {};
    if (!exportName || !*exportName || !ReadNtHeaders(process, module, nt)) return std::nullopt;
    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto directoryAddress = AddressFromRva(module, directory.VirtualAddress,
        sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!directoryAddress || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return std::nullopt;
    IMAGE_EXPORT_DIRECTORY exports = {};
    if (!process.read(*directoryAddress, exports) || !exports.NumberOfNames ||
        !exports.NumberOfFunctions || exports.NumberOfNames > 16384 ||
        exports.NumberOfFunctions > 65536) return std::nullopt;
    const auto namesAddress = AddressFromRva(module, exports.AddressOfNames,
        static_cast<std::size_t>(exports.NumberOfNames) * sizeof(DWORD));
    const auto ordinalsAddress = AddressFromRva(module, exports.AddressOfNameOrdinals,
        static_cast<std::size_t>(exports.NumberOfNames) * sizeof(WORD));
    const auto functionsAddress = AddressFromRva(module, exports.AddressOfFunctions,
        static_cast<std::size_t>(exports.NumberOfFunctions) * sizeof(DWORD));
    if (!namesAddress || !ordinalsAddress || !functionsAddress) return std::nullopt;
    for (DWORD i = 0; i < exports.NumberOfNames; ++i) {
        DWORD nameRva = 0, functionRva = 0;
        WORD functionIndex = 0;
        if (!process.read(*namesAddress + i * sizeof(DWORD), nameRva)) return std::nullopt;
        const auto nameAddress = AddressFromRva(module, nameRva);
        if (!nameAddress || process.readString(*nameAddress, 128) != exportName) continue;
        if (!process.read(*ordinalsAddress + i * sizeof(WORD), functionIndex) ||
            functionIndex >= exports.NumberOfFunctions ||
            !process.read(*functionsAddress + functionIndex * sizeof(DWORD), functionRva))
            return std::nullopt;
        const auto functionAddress = AddressFromRva(module, functionRva);
        if (!functionAddress) return std::nullopt;
        const std::uint64_t exportStart = directory.VirtualAddress;
        const std::uint64_t exportEnd = exportStart + directory.Size;
        if (functionRva >= exportStart && functionRva < exportEnd) return std::nullopt;
        return functionAddress;
    }
    return std::nullopt;
}

std::optional<std::uintptr_t> ResolveRip(std::uintptr_t instruction, int displacementOffset,
                                         int instructionSize, const std::vector<unsigned char>& code,
                                         std::size_t codeOffset) {
    if (displacementOffset < 0 || instructionSize <= 0 ||
        codeOffset + static_cast<std::size_t>(displacementOffset) + sizeof(std::int32_t) > code.size())
        return std::nullopt;
    std::int32_t displacement = 0;
    memcpy(&displacement, code.data() + codeOffset + displacementOffset, sizeof(displacement));
    return instruction + instructionSize + static_cast<std::intptr_t>(displacement);
}

int ClientInterfaceVersion(const std::string& name) {
    static constexpr const char* prefix = "VClient";
    if (name.rfind(prefix, 0) != 0 || name.size() == strlen(prefix)) return -1;
    int version = 0;
    for (std::size_t i = strlen(prefix); i < name.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(name[i]))) return -1;
        const int digit = name[i] - '0';
        if (version > ((std::numeric_limits<int>::max)() - digit) / 10) return -1;
        version = version * 10 + digit;
    }
    return version;
}

std::optional<InterfaceFactory> FindClientInterface(const Process& process, const Module& module,
                                                     std::uintptr_t createInterface) {
    if (!module.contains(createInterface, 1)) return std::nullopt;
    std::vector<unsigned char> code(160);
    if (!process.readBytes(createInterface, code.data(), code.size())) return std::nullopt;
    if (code[0] == 0xE9) {
        const auto target = ResolveRip(createInterface, 1, 5, code, 0);
        if (!target || !module.contains(*target, 1) ||
            !process.readBytes(*target, code.data(), code.size())) return std::nullopt;
        createInterface = *target;
    }
    for (std::size_t i = 0; i + 7 <= code.size(); ++i) {
        if ((code[i] != 0x48 && code[i] != 0x4C) || code[i + 1] != 0x8B ||
            (code[i + 2] & 0xC7) != 0x05) continue;
        const auto global = ResolveRip(createInterface + i, 3, 7, code, i);
        std::uint64_t current = 0;
        if (!global || !module.contains(*global, sizeof(current)) ||
            !process.read(*global, current)) continue;
        std::optional<InterfaceFactory> best;
        int bestVersion = -1;
        for (int guard = 0; current && guard < 1024; ++guard) {
            RemoteInterfaceReg reg = {};
            if (!module.contains(current, sizeof(reg)) || !process.read(current, reg)) break;
            if (!module.contains(reg.name, 1) || (reg.createFn && !module.contains(reg.createFn, 1))) break;
            const std::string name = process.readString(reg.name, 128);
            const int version = ClientInterfaceVersion(name);
            if (version > bestVersion && reg.createFn) {
                bestVersion = version;
                best = InterfaceFactory{ reg.createFn, name };
            }
            current = reg.next;
        }
        if (best) return best;
    }
    return std::nullopt;
}

std::optional<std::uintptr_t> ResolveGlobalFromLea(const Process& process, const Module& module,
                                                   std::uintptr_t function) {
    if (!module.contains(function, 1)) return std::nullopt;
    std::vector<unsigned char> code(64);
    if (!process.readBytes(function, code.data(), code.size())) return std::nullopt;
    for (std::size_t i = 0; i + 7 <= code.size(); ++i) {
        if (code[i] != 0x48 || code[i + 1] != 0x8D || (code[i + 2] & 0xC7) != 0x05)
            continue;
        const auto object = ResolveRip(function + i, 3, 7, code, i);
        std::uint64_t vtable = 0, getAllClasses = 0;
        if (!object || !module.contains(*object, sizeof(vtable)) ||
            !process.read(*object, vtable) || !module.contains(vtable, 9 * sizeof(std::uint64_t)) ||
            !process.read(vtable + 8 * sizeof(std::uint64_t), getAllClasses) ||
            !module.contains(getAllClasses, 1)) continue;
        return object;
    }
    return std::nullopt;
}

bool ValidClientClassHead(const Process& process, const Module& module, std::uintptr_t head) {
    RemoteClientClass clientClass = {};
    if (!module.contains(head, sizeof(clientClass)) || !process.read(head, clientClass) ||
        !module.contains(clientClass.networkName, 1) ||
        !module.contains(clientClass.recvTable, sizeof(RemoteRecvTable))) return false;
    const std::string networkName = process.readString(clientClass.networkName, 128);
    RemoteRecvTable table = {};
    if (networkName.empty() || !process.read(clientClass.recvTable, table) ||
        !module.contains(table.name, 1) || table.propCount < 0 || table.propCount > 4096) return false;
    const std::string tableName = process.readString(table.name, 128);
    return tableName.rfind("DT_", 0) == 0;
}

std::optional<std::uintptr_t> ResolveClientClassHead(const Process& process, const Module& module,
                                                     std::uintptr_t clientObject) {
    if (!module.contains(clientObject, sizeof(std::uint64_t))) return std::nullopt;
    std::uint64_t vtable = 0, function = 0;
    if (!process.read(clientObject, vtable) || !module.contains(vtable, 9 * sizeof(std::uint64_t)) ||
        !process.read(vtable + 8 * sizeof(std::uint64_t), function) || !module.contains(function, 1))
        return std::nullopt;
    std::vector<unsigned char> code(96);
    if (!process.readBytes(function, code.data(), code.size())) return std::nullopt;
    for (std::size_t i = 0; i + 7 <= code.size(); ++i) {
        if (code[i] != 0x48 || code[i + 1] != 0x8B || (code[i + 2] & 0xC7) != 0x05) continue;
        const auto global = ResolveRip(function + i, 3, 7, code, i);
        std::uint64_t head = 0;
        if (global && module.contains(*global, sizeof(head)) && process.read(*global, head) &&
            ValidClientClassHead(process, module, head)) return head;
    }
    return std::nullopt;
}

struct Netvar {
    std::string root, table, name;
    int offset = 0;
};

void CollectTable(const Process& process, const Module& module, std::uintptr_t tableAddress,
                  const std::string& root,
                  int baseOffset, int depth, std::vector<std::uintptr_t>& ancestors,
                  std::vector<Netvar>& output) {
    if (!tableAddress || !module.contains(tableAddress, sizeof(RemoteRecvTable)) ||
        depth >= 24 || output.size() >= 50000 ||
        std::find(ancestors.begin(), ancestors.end(), tableAddress) != ancestors.end()) return;
    RemoteRecvTable table = {};
    if (!process.read(tableAddress, table) || table.propCount < 0 || table.propCount > 4096 ||
        !module.contains(table.name, 1) ||
        (table.propCount > 0 && !module.contains(table.props,
            static_cast<std::size_t>(table.propCount) * sizeof(RemoteRecvProp)))) return;
    const std::string tableName = process.readString(table.name);
    if (tableName.empty()) return;
    ancestors.push_back(tableAddress);
    for (int i = 0; i < table.propCount && output.size() < 50000; ++i) {
        RemoteRecvProp prop = {};
        if (!process.read(table.props + static_cast<std::uintptr_t>(i) * sizeof(prop), prop) ||
            !module.contains(prop.name, 1)) continue;
        const std::string propertyName = process.readString(prop.name);
        if (propertyName.empty()) continue;
        const std::int64_t candidate = static_cast<std::int64_t>(baseOffset) + prop.offset;
        if (candidate < (std::numeric_limits<int>::min)() ||
            candidate > (std::numeric_limits<int>::max)()) continue;
        const int absolute = static_cast<int>(candidate);
        output.push_back({ root, tableName, propertyName, absolute });
        if (prop.type == 6 && prop.dataTable)
            CollectTable(process, module, prop.dataTable, root, absolute, depth + 1, ancestors, output);
    }
    ancestors.pop_back();
}

std::vector<Netvar> CollectNetvars(const Process& process, const Module& module,
                                   std::uintptr_t classHead) {
    std::vector<Netvar> output;
    for (int guard = 0; classHead && guard < 4096; ++guard) {
        RemoteClientClass clientClass = {};
        if (!module.contains(classHead, sizeof(clientClass)) || !process.read(classHead, clientClass) ||
            !module.contains(clientClass.networkName, 1)) break;
        const std::string root = process.readString(clientClass.networkName);
        if (!root.empty() && clientClass.recvTable) {
            std::vector<std::uintptr_t> ancestors;
            CollectTable(process, module, clientClass.recvTable, root, 0, 0, ancestors, output);
        }
        classHead = clientClass.next;
    }
    return output;
}

std::vector<Netvar> CanonicalNetvars(std::vector<Netvar> netvars) {
    std::sort(netvars.begin(), netvars.end(), [](const Netvar& left, const Netvar& right) {
        if (left.table != right.table) return left.table < right.table;
        if (left.name != right.name) return left.name < right.name;
        return left.offset < right.offset;
    });
    netvars.erase(std::unique(netvars.begin(), netvars.end(), [](const Netvar& left, const Netvar& right) {
        return left.table == right.table && left.name == right.name && left.offset == right.offset;
    }), netvars.end());
    for (Netvar& netvar : netvars) netvar.root.clear();
    return netvars;
}

void WriteJsonString(std::ostream& output, const std::string& value) {
    output << '"';
    for (const unsigned char c : value) {
        if (c == '\\') output << "\\\\";
        else if (c == '"') output << "\\\"";
        else if (c == '\n') output << "\\n";
        else if (c == '\r') output << "\\r";
        else if (c == '\t') output << "\\t";
        else if (c < 0x20) {
            static constexpr char hex[] = "0123456789ABCDEF";
            output << "\\u00" << hex[(c >> 4) & 0xF] << hex[c & 0xF];
        } else output << c;
    }
    output << '"';
}

bool WriteReport(const std::filesystem::path& path, const Module& module, DWORD timestamp, DWORD imageSize,
                 const std::vector<SignatureResult>& signatures, const std::vector<Netvar>& netvars,
                 const std::string& netvarStatus) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    std::string moduleName;
    moduleName.reserve(module.name.size());
    for (const wchar_t c : module.name)
        moduleName.push_back(c <= 0x7F ? static_cast<char>(c) : '?');
    output << "{\n  \"schema\": 1,\n  \"module\": ";
    WriteJsonString(output, moduleName);
    output << ",\n  \"fingerprint\": {\"pe_timestamp\": " << timestamp
           << ", \"image_size\": " << imageSize << "},\n";
    output << "  \"signatures\": [\n";
    for (std::size_t i = 0; i < signatures.size(); ++i) {
        output << "    {\"name\": "; WriteJsonString(output, signatures[i].name);
        output << ", \"required\": " << (signatures[i].required ? "true" : "false")
               << ", \"found\": " << (signatures[i].found ? "true" : "false")
               << ", \"match_count\": " << signatures[i].matchCount;
        if (signatures[i].found) output << ", \"rva\": \"0x" << std::hex << (signatures[i].value - module.base) << std::dec << "\"";
        if (!signatures[i].error.empty()) {
            output << ", \"error\": ";
            WriteJsonString(output, signatures[i].error);
        }
        output << "}" << (i + 1 == signatures.size() ? "\n" : ",\n");
    }
    output << "  ],\n  \"netvar_status\": "; WriteJsonString(output, netvarStatus);
    output << ",\n  \"netvars\": [\n";
    for (std::size_t i = 0; i < netvars.size(); ++i) {
        output << "    {\"table\": "; WriteJsonString(output, netvars[i].table);
        output << ", \"name\": "; WriteJsonString(output, netvars[i].name);
        output << ", \"offset\": " << netvars[i].offset << "}" << (i + 1 == netvars.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
    output.flush();
    return output.good();
}

bool WriteDiagnostics(const std::filesystem::path& path, DWORD pid, const Module& module,
                      const std::vector<SignatureResult>& signatures,
                      std::size_t rawNetvarCount, std::size_t canonicalNetvarCount,
                      const std::string& netvarStatus, bool success) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output << "{\n  \"schema\": 1,\n  \"success\": " << (success ? "true" : "false")
           << ",\n  \"pid\": " << pid << ",\n  \"module_base\": \"0x" << std::hex
           << module.base << std::dec << "\",\n  \"netvar_status\": ";
    WriteJsonString(output, netvarStatus);
    output << ",\n  \"raw_netvar_count\": " << rawNetvarCount
           << ",\n  \"canonical_netvar_count\": " << canonicalNetvarCount
           << ",\n  \"signature_failures\": [\n";
    bool first = true;
    for (const SignatureResult& signature : signatures) {
        if (!signature.required || signature.found) continue;
        if (!first) output << ",\n";
        output << "    {\"name\": "; WriteJsonString(output, signature.name);
        output << ", \"match_count\": " << signature.matchCount << ", \"error\": ";
        WriteJsonString(output, signature.error);
        output << "}";
        first = false;
    }
    if (!first) output << '\n';
    output << "  ]\n}\n";
    output.flush();
    return output.good();
}

bool ReplaceFile(const std::filesystem::path& temporary, const std::filesystem::path& destination) {
    return MoveFileExW(temporary.c_str(), destination.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

std::optional<std::filesystem::path> ExecutableDirectory() {
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD copied = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!copied) return std::nullopt;
        if (copied < buffer.size() - 1)
            return std::filesystem::path(std::wstring(buffer.data(), copied)).parent_path();
        if (buffer.size() >= 32768) return std::nullopt;
        buffer.resize(buffer.size() * 2);
    }
}

bool ParsePid(const wchar_t* text, DWORD& pid) {
    if (!text || !*text) return false;
    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text, &end, 10);
    if (!end || *end || value == 0) return false;
    pid = static_cast<DWORD>(value);
    return true;
}

bool LaunchedInOwnConsole() {
    DWORD processIds[8] = {};
    const DWORD count = GetConsoleProcessList(processIds, static_cast<DWORD>(std::size(processIds)));
    return count == 1 && processIds[0] == GetCurrentProcessId();
}

int Finish(int code, bool pauseBeforeExit) {
    if (pauseBeforeExit) {
        std::wcout << L"\nPress Enter to close...";
        std::wcin.get();
    }
    return code;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    const bool pauseBeforeExit = LaunchedInOwnConsole();
    const auto executableDirectory = ExecutableDirectory();
    if (!executableDirectory) {
        std::wcerr << L"Could not determine the iosdumper executable directory.\n";
        return Finish(1, pauseBeforeExit);
    }
    DWORD pid = 0;
    if (argc > 1) {
        if (!ParsePid(argv[1], pid)) {
            std::wcerr << L"Usage: iosdumper.exe [IOSoccer PID]\n";
            return Finish(2, pauseBeforeExit);
        }
    } else {
        const auto found = FindProcessId(L"IOSoccer.exe");
        if (!found) {
            std::wcerr << L"IOSoccer.exe is not running. Start the game or pass its PID.\n";
            return Finish(3, pauseBeforeExit);
        }
        pid = *found;
    }

    const auto signaturePath = *executableDirectory / "signatures.json";
    DumperConfig config;
    std::string configError;
    if (!LoadConfig(signaturePath, config, configError)) {
        std::wcerr << L"Invalid signatures.json: "
                   << std::wstring(configError.begin(), configError.end()) << L"\n";
        return Finish(6, pauseBeforeExit);
    }

    Process process(pid);
    if (!process.valid()) {
        std::wcerr << L"Could not open PID " << pid << L" for read-only inspection (error " << GetLastError() << L").\n";
        return Finish(4, pauseBeforeExit);
    }
    const auto module = FindModule(pid, config.module);
    if (!module) {
        std::wcerr << config.module << L" is not loaded in PID " << pid << L".\n";
        return Finish(5, pauseBeforeExit);
    }

    IMAGE_NT_HEADERS64 nt = {};
    if (!ReadNtHeaders(process, *module, nt)) {
        std::wcerr << config.module << L" does not expose a valid x64 PE header.\n";
        return Finish(7, pauseBeforeExit);
    }

    std::vector<SignatureResult> signatureResults;
    bool requiredSignaturesOk = true;
    for (const Signature& signature : config.signatures) {
        SignatureResult result;
        result.name = signature.name;
        result.required = signature.required;
        const auto matches = ScanModule(process, *module, ParsePattern(signature.pattern));
        result.matchCount = matches.size();
        if (matches.size() == 1) {
            result.value = matches[0];
            if (signature.kind == "rip_rel32") {
                std::int32_t displacement = 0;
                if (!module->contains(matches[0], static_cast<std::size_t>(signature.instructionSize)) ||
                    !process.read(matches[0] + signature.dispOffset, displacement))
                    result.error = "could not read RIP displacement";
                else {
                    result.value = matches[0] + signature.instructionSize +
                        static_cast<std::intptr_t>(displacement);
                    if (!module->contains(result.value, 1))
                        result.error = "resolved address is outside the configured module";
                    else result.found = true;
                }
            } else {
                result.found = true;
            }
        } else if (matches.empty()) {
            result.error = "pattern not found";
        } else {
            result.error = "pattern is ambiguous";
        }
        if (result.required && !result.found) requiredSignaturesOk = false;
        signatureResults.push_back(result);
    }

    std::vector<Netvar> rawNetvars;
    std::string netvarStatus = "CreateInterface/VClientNNN unavailable";
    if (const auto createInterface = ExportAddress(process, *module, "CreateInterface")) {
        if (const auto clientInterface = FindClientInterface(process, *module, *createInterface)) {
            if (const auto clientObject = ResolveGlobalFromLea(process, *module, clientInterface->createFn)) {
                if (const auto classHead = ResolveClientClassHead(process, *module, *clientObject)) {
                    rawNetvars = CollectNetvars(process, *module, *classHead);
                    netvarStatus = rawNetvars.empty()
                        ? clientInterface->version + ": GetAllClasses returned no readable RecvTables"
                        : "ok (" + clientInterface->version + ")";
                } else netvarStatus = "Could not resolve GetAllClasses client-class head";
            } else netvarStatus = "Could not resolve " + clientInterface->version + " singleton";
        } else netvarStatus = "No VClientNNN entry found in CreateInterface registry";
    } else netvarStatus = "CreateInterface export not found";
    std::vector<Netvar> netvars = CanonicalNetvars(rawNetvars);
    const bool netvarsOk = !netvars.empty() && netvarStatus.rfind("ok (", 0) == 0;
    const bool overallSuccess = requiredSignaturesOk && netvarsOk;

    const auto reportDirectory = *executableDirectory / "out";
    std::error_code directoryError;
    std::filesystem::create_directories(reportDirectory, directoryError);
    if (directoryError) {
        std::wcerr << L"Could not create the output directory.\n";
        return Finish(8, pauseBeforeExit);
    }
    const auto reportPath = reportDirectory / "iosoccer_offsets.json";
    const auto reportTemporary = reportDirectory / "iosoccer_offsets.json.tmp";
    const auto diagnosticsPath = reportDirectory / "diagnostics.json";
    const auto diagnosticsTemporary = reportDirectory / "diagnostics.json.tmp";
    if (!WriteReport(reportTemporary, *module, nt.FileHeader.TimeDateStamp,
            nt.OptionalHeader.SizeOfImage, signatureResults, netvars, netvarStatus) ||
        !ReplaceFile(reportTemporary, reportPath)) {
        std::wcerr << L"Could not write " << reportPath.wstring() << L".\n";
        return Finish(9, pauseBeforeExit);
    }
    if (!WriteDiagnostics(diagnosticsTemporary, pid, *module, signatureResults,
            rawNetvars.size(), netvars.size(), netvarStatus, overallSuccess) ||
        !ReplaceFile(diagnosticsTemporary, diagnosticsPath)) {
        std::wcerr << L"Could not write " << diagnosticsPath.wstring() << L".\n";
        return Finish(9, pauseBeforeExit);
    }

    const std::size_t resolvedSignatures = static_cast<std::size_t>(std::count_if(
        signatureResults.begin(), signatureResults.end(),
        [](const SignatureResult& result) { return result.found; }));
    std::wcout << L"Signatures: " << resolvedSignatures << L"/" << signatureResults.size()
               << L". Netvars: " << rawNetvars.size() << L" raw, " << netvars.size()
               << L" canonical.\nReport: " << reportPath.wstring()
               << L"\nDiagnostics: " << diagnosticsPath.wstring() << L"\n";
    if (!overallSuccess) {
        std::wcerr << L"Dump completed with required failures. See diagnostics.json.\n";
        return Finish(10, pauseBeforeExit);
    }
    return Finish(0, pauseBeforeExit);
}
