#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <boost/program_options.hpp>

#include <cstdlib>
#include <filesystem> 
#include <fstream>
#include <print>
#include <stdexcept>
#include <string>
#include <sstream>

int main(int argc, char *argv[]) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        if (options.GetIsPrintHelp())
            return EXIT_SUCCESS;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        auto checkFile = [](const std::string& filePath){
            if (!std::filesystem::exists(filePath))
                throw std::runtime_error(filePath + " not found");
        };

        auto getInputStreamByFileBinContent = [](const std::string& filePath){
            std::ifstream inputFile(filePath, std::ios::binary);
            std::stringstream ss;
            ss << inputFile.rdbuf();
            return ss;
        };

        auto saveOutputStream = [&](std::stringstream&& ss, const std::string& filePath){
            std::ofstream outputFile(filePath, std::ios::binary);
            outputFile << ss.rdbuf();
        };

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:{
            checkFile(options.GetInputFile());
            checkFile(options.GetOutputFile());
            auto inputStream {getInputStreamByFileBinContent(options.GetInputFile())};
            std::stringstream outputStream;
            cryptoCtx.EncryptFile(inputStream, outputStream, options.GetPassword());
            saveOutputStream(std::move(outputStream), options.GetOutputFile());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT:{
            checkFile(options.GetInputFile());
            checkFile(options.GetOutputFile());
            auto inputStream {getInputStreamByFileBinContent(options.GetInputFile())};
            std::stringstream outputStream;
            cryptoCtx.DecryptFile(inputStream, outputStream, options.GetPassword());
            saveOutputStream(std::move(outputStream), options.GetOutputFile());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM:{
            checkFile(options.GetInputFile());
            auto inputStream {getInputStreamByFileBinContent(options.GetInputFile())};
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