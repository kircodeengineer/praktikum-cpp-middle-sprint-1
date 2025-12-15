#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <string_view>
#include <unordered_map>

namespace CryptoGuard {
using namespace std::literals;
namespace po = boost::program_options;
class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM
    };

    struct Literals {
		Literals() = delete;
        constexpr static std::string_view COMMAND = "command"sv;
		constexpr static std::string_view INPUT = "input"sv;
		constexpr static std::string_view OUTPUT = "output"sv;
		constexpr static std::string_view PASSWORD = "password"sv;
		constexpr static std::string_view ENCRYPT = "encrypt"sv;
		constexpr static std::string_view DECRYPT = "decrypt"sv;
		constexpr static std::string_view CHECKSUM = "checksum"sv;
        constexpr static std::string_view HELP = "help"sv;
	};

    void Parse(int argc, const char *argv[]);

    [[nodiscard]] COMMAND_TYPE GetCommand() const { return command_; }
    [[nodiscard]] std::string GetInputFile() const { return inputFile_; }
    [[nodiscard]] std::string GetOutputFile() const { return outputFile_; }
    [[nodiscard]] std::string GetPassword() const { return password_; }
    [[nodiscard]] bool GetIsPrintHelp() const { return isPrintHelp_; }
    [[nodiscard]] po::options_description GetOptionsDescription() const { return desc_; }

private:
    COMMAND_TYPE command_;
    std::string commandStr_ {};
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {Literals::ENCRYPT, ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {Literals::DECRYPT, ProgramOptions::COMMAND_TYPE::DECRYPT},
        {Literals::CHECKSUM, ProgramOptions::COMMAND_TYPE::CHECKSUM}
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;
    bool isPrintHelp_ {};

    po::options_description desc_;
};

}  // namespace CryptoGuard
