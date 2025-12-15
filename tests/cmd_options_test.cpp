#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include "cmd_options.h"

using namespace CryptoGuard;

class ArgList{
    public:
        explicit ArgList(const std::vector<std::string>& args){
            args_str_.emplace_back("CryptoGuard");
            for (const auto& arg : args)
                args_str_.emplace_back(arg);
            
            argv_.reserve(args_str_.size());
            for (auto& arg_str : args_str_)
                argv_.emplace_back(arg_str.data());
        }

        [[nodiscard]] std::int32_t GetArgc() const {
            return static_cast<std::int32_t>(argv_.size());
        };

        [[nodiscard]] const char** GetArgv() const noexcept {
            return const_cast<const char**>(argv_.data());
        }

    private:
        std::vector<std::string> args_str_;
        std::vector<char*> argv_;
};

TEST(ProgramOptionsTest, TestHelpOptionShort){
    ArgList argList({"-h"});
    ProgramOptions progOptions;
    progOptions.Parse(argList.GetArgc(), argList.GetArgv());
    EXPECT_TRUE(progOptions.GetIsPrintHelp());
}

TEST(ProgramOptionsTest, TestHelpOptionLong){
    ArgList argList({"--help"});
    ProgramOptions progOptions;
    progOptions.Parse(argList.GetArgc(), argList.GetArgv());
    EXPECT_TRUE(progOptions.GetIsPrintHelp());
}

TEST(ProgramOptionsTest, TestUnknownCommandShort){
    ArgList argList({"-c", "log"});
    ProgramOptions progOptions;
    EXPECT_THROW(progOptions.Parse(argList.GetArgc(), argList.GetArgv()), std::invalid_argument);
}

TEST(ProgramOptionsTest, TestUnknownCommandLong){
    ArgList argList({"--command", "log"});
    ProgramOptions progOptions;
    EXPECT_THROW(progOptions.Parse(argList.GetArgc(), argList.GetArgv()), std::invalid_argument);
}

TEST(ProgramOptionsTest, TestMissingOneRequiredOption){
    ArgList argList({"-c", "encrypt", "-i", "inputFile", "-o", "outputFile"});
    ProgramOptions progOptions;
    EXPECT_THROW(progOptions.Parse(argList.GetArgc(), argList.GetArgv()), std::invalid_argument);
}

TEST(ProgramOptionsTest, TestMissingTwoRequiredOption){
    ArgList argList({"-c", "encrypt", "-i", "inputFile"});
    ProgramOptions progOptions;
    EXPECT_THROW(progOptions.Parse(argList.GetArgc(), argList.GetArgv()), std::invalid_argument);
}

TEST(ProgramOptionsTest, TestMissingAllRequiredOption){
    ArgList argList({"-c", "encrypt"});
    ProgramOptions progOptions;
    EXPECT_THROW(progOptions.Parse(argList.GetArgc(), argList.GetArgv()), std::invalid_argument);
}

TEST(ProgramOptionsTest, TestSuccessChecksumOption){
    std::string inputFile {"inputFile"};
    ArgList argList({"-c", "checksum", "-i", inputFile});
    ProgramOptions progOptions;
    progOptions.Parse(argList.GetArgc(), argList.GetArgv());
    EXPECT_EQ(progOptions.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(progOptions.GetInputFile(), inputFile);
}

TEST(ProgramOptionsTest, TestSuccessEncryptOption){
    std::string inputFile {"inputFile"};
    std::string outputFile {"outputFile"};
    std::string password {"password"};
    ArgList argList({"-c", "encrypt", "-i", inputFile, "-o", outputFile, "-p", password});
    ProgramOptions progOptions;
    progOptions.Parse(argList.GetArgc(), argList.GetArgv());
    EXPECT_EQ(progOptions.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(progOptions.GetInputFile(), inputFile);
    EXPECT_EQ(progOptions.GetOutputFile(), outputFile);
    EXPECT_EQ(progOptions.GetPassword(), password);
}

TEST(ProgramOptionsTest, TestSuccessDecryptOption){
    std::string inputFile {"inputFile"};
    std::string outputFile {"outputFile"};
    std::string password {"password"};
    ArgList argList({"-c", "decrypt", "-i", inputFile, "-o", outputFile, "-p", password});
    ProgramOptions progOptions;
    progOptions.Parse(argList.GetArgc(), argList.GetArgv());
    EXPECT_EQ(progOptions.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(progOptions.GetInputFile(), inputFile);
    EXPECT_EQ(progOptions.GetOutputFile(), outputFile);
    EXPECT_EQ(progOptions.GetPassword(), password);
}