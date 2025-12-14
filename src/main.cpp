#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <boost/program_options.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        if (options.GetIsPrintHelp()){
            return EXIT_SUCCESS;
        }

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        std::ifstream inputFile;
        std::stringstream inputStream;
        std::ofstream outputFile;
        std::string password {};
        std::stringstream outputStream;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            inputFile.open("document.txt", std::ios::binary);
            inputStream << inputFile.rdbuf();
            inputFile.close();
            password = "my-secret-password";
            cryptoCtx.EncryptFile(inputStream, outputStream, password);
            outputFile.open("document.enc", std::ios::binary);
            outputFile << outputStream.rdbuf();
            outputFile.close();
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            inputFile.open("document.enc", std::ios::binary);
            inputStream << inputFile.rdbuf();
            inputFile.close();
            password = "my-secret-password";
            cryptoCtx.DecryptFile(inputStream, outputStream, password);
            outputFile.open("document.denc", std::ios::binary);
            outputFile << outputStream.rdbuf();
            outputFile.close();
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            cryptoCtx.CalculateChecksum(inputStream);
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return EXIT_SUCCESS;
}