#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <boost/program_options.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <print>
#include <sstream>
#include <stdexcept>
#include <string>

int main(int argc, const char *argv[]) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        if (options.GetIsPrintHelp()) {
            std::stringstream ss;
            ss << options.GetOptionsDescription() << std::endl;
            std::print("{}", ss.str());
            return EXIT_SUCCESS;
        }

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        auto checkFile = [](const std::string &filePath) {
            if (!std::filesystem::exists(filePath))
                throw std::runtime_error(filePath + " not found");
        };

        auto getInputStreamByFileBinContent = [](const std::string &filePath) {
            std::ifstream inputFile(filePath, std::ios::binary);
            std::stringstream ss;
            ss << inputFile.rdbuf();
            return ss;
        };

        auto saveOutputStream = [&](std::stringstream &&ss, const std::string &filePath) {
            std::ofstream outputFile(filePath, std::ios::binary);
            outputFile << ss.rdbuf();
        };
        checkFile(options.GetInputFile());
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto inputStream{getInputStreamByFileBinContent(options.GetInputFile())};
            std::stringstream outputStream;
            cryptoCtx.EncryptFile(inputStream, outputStream, options.GetPassword());
            saveOutputStream(std::move(outputStream), options.GetOutputFile());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            auto inputStream{getInputStreamByFileBinContent(options.GetInputFile())};
            std::stringstream outputStream;
            cryptoCtx.DecryptFile(inputStream, outputStream, options.GetPassword());
            saveOutputStream(std::move(outputStream), options.GetOutputFile());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            auto inputStream{getInputStreamByFileBinContent(options.GetInputFile())};
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputStream));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}