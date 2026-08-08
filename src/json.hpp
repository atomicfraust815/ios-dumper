#pragma once

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Json {
enum class Type { Null, Boolean, Number, String, Array, Object };

struct Value {
    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string string;
    std::vector<Value> array;
    std::map<std::string, Value> object;

    const Value* Find(const char* key) const {
        if (type != Type::Object || !key) return nullptr;
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }
};

class Parser {
public:
    explicit Parser(std::string_view input) : input_(input) {}

    bool Parse(Value& output, std::string& error) {
        error_.clear();
        position_ = 0;
        SkipWhitespace();
        if (!ParseValue(output)) {
            error = error_;
            return false;
        }
        SkipWhitespace();
        if (position_ != input_.size()) {
            SetError("unexpected characters after the root value");
            error = error_;
            return false;
        }
        error.clear();
        return true;
    }

private:
    void SkipWhitespace() {
        while (position_ < input_.size()) {
            const char c = input_[position_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++position_;
        }
    }

    void SetError(const char* message) {
        if (!error_.empty()) return;
        error_ = "JSON error at byte " + std::to_string(position_) + ": " + message;
    }

    bool Consume(char expected) {
        if (position_ >= input_.size() || input_[position_] != expected) return false;
        ++position_;
        return true;
    }

    bool ParseValue(Value& output) {
        SkipWhitespace();
        if (position_ >= input_.size()) {
            SetError("expected a value");
            return false;
        }
        switch (input_[position_]) {
        case '{': return ParseObject(output);
        case '[': return ParseArray(output);
        case '"':
            output = {};
            output.type = Type::String;
            return ParseString(output.string);
        case 't': return ParseLiteral("true", Type::Boolean, output, true);
        case 'f': return ParseLiteral("false", Type::Boolean, output, false);
        case 'n': return ParseLiteral("null", Type::Null, output, false);
        default:
            if (input_[position_] == '-' ||
                (input_[position_] >= '0' && input_[position_] <= '9'))
                return ParseNumber(output);
            SetError("invalid value");
            return false;
        }
    }

    bool ParseLiteral(std::string_view literal, Type type, Value& output, bool boolean) {
        if (input_.substr(position_, literal.size()) != literal) {
            SetError("invalid literal");
            return false;
        }
        position_ += literal.size();
        output = {};
        output.type = type;
        output.boolean = boolean;
        return true;
    }

    static void AppendUtf8(std::string& output, unsigned int codepoint) {
        if (codepoint <= 0x7F) output.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7FF) {
            output.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else {
            output.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        }
    }

    static int HexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool ParseString(std::string& output) {
        if (!Consume('"')) {
            SetError("expected a string");
            return false;
        }
        output.clear();
        while (position_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') return true;
            if (c < 0x20) {
                SetError("unescaped control character in string");
                return false;
            }
            if (c != '\\') {
                output.push_back(static_cast<char>(c));
                continue;
            }
            if (position_ >= input_.size()) {
                SetError("unterminated escape sequence");
                return false;
            }
            const char escaped = input_[position_++];
            switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u': {
                if (position_ + 4 > input_.size()) {
                    SetError("incomplete unicode escape");
                    return false;
                }
                unsigned int codepoint = 0;
                for (int i = 0; i < 4; ++i) {
                    const int digit = HexDigit(input_[position_++]);
                    if (digit < 0) {
                        SetError("invalid unicode escape");
                        return false;
                    }
                    codepoint = (codepoint << 4) | static_cast<unsigned int>(digit);
                }
                if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
                    SetError("unicode surrogate pairs are not supported in configuration");
                    return false;
                }
                AppendUtf8(output, codepoint);
                break;
            }
            default:
                SetError("invalid escape sequence");
                return false;
            }
        }
        SetError("unterminated string");
        return false;
    }

    bool ParseNumber(Value& output) {
        const std::size_t start = position_;
        if (input_[position_] == '-') ++position_;
        if (position_ >= input_.size()) {
            SetError("incomplete number");
            return false;
        }
        if (input_[position_] == '0') ++position_;
        else {
            if (input_[position_] < '1' || input_[position_] > '9') {
                SetError("invalid number");
                return false;
            }
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
                ++position_;
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const std::size_t fractionStart = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
                ++position_;
            if (position_ == fractionStart) {
                SetError("fraction requires digits");
                return false;
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-'))
                ++position_;
            const std::size_t exponentStart = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
                ++position_;
            if (position_ == exponentStart) {
                SetError("exponent requires digits");
                return false;
            }
        }
        const std::string token(input_.substr(start, position_ - start));
        char* end = nullptr;
        errno = 0;
        const double number = std::strtod(token.c_str(), &end);
        if (errno == ERANGE || !end || *end || !std::isfinite(number)) {
            SetError("number is out of range");
            return false;
        }
        output = {};
        output.type = Type::Number;
        output.number = number;
        return true;
    }

    bool ParseArray(Value& output) {
        Consume('[');
        output = {};
        output.type = Type::Array;
        SkipWhitespace();
        if (Consume(']')) return true;
        for (;;) {
            Value element;
            if (!ParseValue(element)) return false;
            output.array.push_back(std::move(element));
            SkipWhitespace();
            if (Consume(']')) return true;
            if (!Consume(',')) {
                SetError("expected ',' or ']' in array");
                return false;
            }
            SkipWhitespace();
        }
    }

    bool ParseObject(Value& output) {
        Consume('{');
        output = {};
        output.type = Type::Object;
        SkipWhitespace();
        if (Consume('}')) return true;
        for (;;) {
            std::string key;
            if (!ParseString(key)) return false;
            SkipWhitespace();
            if (!Consume(':')) {
                SetError("expected ':' after object key");
                return false;
            }
            Value value;
            if (!ParseValue(value)) return false;
            if (!output.object.emplace(std::move(key), std::move(value)).second) {
                SetError("duplicate object key");
                return false;
            }
            SkipWhitespace();
            if (Consume('}')) return true;
            if (!Consume(',')) {
                SetError("expected ',' or '}' in object");
                return false;
            }
            SkipWhitespace();
        }
    }

    std::string_view input_;
    std::size_t position_ = 0;
    std::string error_;
};
} // namespace Json
