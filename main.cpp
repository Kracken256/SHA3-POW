#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "crypto.hpp"

bool is_number(const std::string &s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it))
        ++it;
    return !s.empty() && it == s.end();
}

int main(int argc, char *argv[])
{
    std::vector<std::string> arguments(argv + 1, argv + argc);
    bool useSTDIN = true;
    std::string data;
    int difficultly = 8;
    for (uint64_t i = 0; i < arguments.size(); i++)
    {
        if (arguments[i] == "--data" || arguments[i] == "-data")
        {
            useSTDIN = false;
            if (arguments.size() <= (i + 1))
            {
                printf("Specify data to compute POW on.\n");
                return -1;
            }
            data = arguments[i + 1];
        }
        else if (arguments[i] == "--difficulty" || arguments[i] == "-d" || arguments[i] == "--diff")
        {
            if (arguments.size() <= (i + 1))
            {
                printf("Difficulty value missing.\n");
                return -2;
            }
            if (!is_number(arguments[i + 1]))
            {
                printf("Difficulty value is not a number.\n");
                return -3;
            }
            difficultly = std::atoi(arguments[i + 1].c_str());
            std::cout << "Difficulty set to: " + std::to_string(difficultly) << " bits." << std::endl;
        }
    }
    if (useSTDIN)
    {
        char ch;
        while (std::cin.get(ch))
        {
            data += ch;
        }
    }
    if (data.length() == 0)
    {
        printf("WARNING: Input data is empty.");
    }
    uint64_t nonce = 0;
    bool status = SHA3_POW::Compute_SHA3_POW(data, difficultly, &nonce);
    if (!status)
    {
        printf("ERROR: Can not compute POW.\n");
        return -4;
    }
    std::cout << "Best nonce: " << nonce << std::endl;
    return 0;
}