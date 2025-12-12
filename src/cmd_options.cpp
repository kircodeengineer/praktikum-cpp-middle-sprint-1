#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    std::string command {};

    desc_.add_options()("help,h", "produce help message")
        ("command,c", po::value(&command)->value_name("string"s), "command")
        ("input,i", po::value(&inputFile_)->value_name("file"s), "input file root")
        ("output,o", po::value(&outputFile_)->value_name("file"s), "output files root")
        ("password,p", po::value(&password_)->value_name("string"s), "pass");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains("help"s)) {
        std::cout << desc_ << std::endl;
    }

    if (vm.contains("command"s)) {
        command_ = commandMapping_.at(command);
    }
}

}  // namespace CryptoGuard
