#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()(static_cast<const char*>((std::string(Literals::HELP) + ",h"s).c_str()), "produce help message")
    (static_cast<const char*>((std::string(Literals::COMMAND) + ",c"s).c_str()), po::value(&commandStr_)->value_name("string"s), "command")
    (static_cast<const char*>((std::string(Literals::INPUT) + ",i"s).c_str()), po::value(&inputFile_)->value_name("file"s), "input file root")
    (static_cast<const char*>((std::string(Literals::OUTPUT) + ",o"s).c_str()), po::value(&outputFile_)->value_name("file"s), "output files root")
    (static_cast<const char*>((std::string(Literals::PASSWORD) + ",p"s).c_str()), po::value(&password_)->value_name("string"s), "pass");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains(std::string(Literals::HELP))) {
        std::cout << desc_ << std::endl;
        isPrintHelp_ = true;
        return;
    }
    
    if (vm.contains(std::string(Literals::COMMAND))) {
        if (commandMapping_.contains(commandStr_)) {
            command_ = commandMapping_.at(commandStr_);
            switch (command_) {
                case COMMAND_TYPE::ENCRYPT:
                case COMMAND_TYPE::DECRYPT:
                    {
                        const auto required = {std::string(Literals::INPUT), 
                            std::string(Literals::OUTPUT), 
                            std::string(Literals::PASSWORD)};
                        std::string noOpts {};
                        for (const auto& opt : required) {
                            if (!vm.contains(opt)) 
                                noOpts += opt + " "s;
                        }
                        if (!noOpts.empty())
                            throw std::invalid_argument(
                                "No options [ " + std::string(noOpts) + 
                                "] required when " + commandStr_ + " is specified"
                            );
                        break;
                    }
                case COMMAND_TYPE::CHECKSUM:
                    if (!vm.contains("input"s)) 
                        throw std::invalid_argument(
                            "No [ input ] required when " + commandStr_ + " is specified"
                        );
                    break;
                default:
                    break;
            }
        } else {
            throw std::invalid_argument("Unknown command - " + commandStr_);
        }
    }
}

}  // namespace CryptoGuard
