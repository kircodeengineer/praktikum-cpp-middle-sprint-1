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

        std::stringstream input_test;
        std::stringstream output_test;

        std::ifstream inputFile("document.txt", std::ios::binary);
        std::stringstream inputStream;
            inputStream << inputFile.rdbuf();
            std::ofstream outputFile("document.enc", std::ios::binary);
            std::string password = "my-secret-password";
            std::stringstream outputStream;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(inputStream, outputStream, password);
            outputFile << outputStream.rdbuf();
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(input_test, output_test, "test");
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            cryptoCtx.CalculateChecksum(input_test);
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