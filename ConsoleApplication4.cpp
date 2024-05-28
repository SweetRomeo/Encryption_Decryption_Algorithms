#pragma warning(disable : 4996)

#include "SecurityUtil.h"
#include <openssl/cast.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <concepts>


void TestAlgorithms() {
    std::vector<std::unique_ptr<Algorithm>> algorithms;
    algorithms.emplace_back(std::make_unique<AES>());
    algorithms.emplace_back(std::make_unique<Seed>());
    algorithms.emplace_back(std::make_unique<Rsa>());
    algorithms.emplace_back(std::make_unique<Cast5>());
    algorithms.emplace_back(std::make_unique<Camellia>());
    algorithms.emplace_back(std::make_unique<Dsa>());
    algorithms.emplace_back(std::make_unique<Dh>());
    algorithms.emplace_back(std::make_unique<Ecdsa>());
    //algorithms.emplace_back(std::make_unique<Idea>());
    //algorithms.emplace_back(std::make_unique<Blowfish>());

    unsigned char key[AES_BLOCK_SIZE] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };
    
    for (const auto& algorithm : algorithms) {
        auto start = std::chrono::system_clock::now();
        std::stringstream algoType;
        algorithm->initializeKey(key, iv);

        const std::type_info& typeInfo = typeid(*algorithm);
        algoType << typeInfo.name() << std::endl;
        std::string algoTypeTemp = algoType.str();
        algoTypeTemp = algoTypeTemp.substr(6);
        std::cout << "Algorithm Name : " << algoTypeTemp;
        //std::cout << "Algorithm Type : ";
        //std::cout << std::is_base_of_v<SimetricAlgorithm, > << '\n';
        std::string plaintext = "Hello, World!";
        std::string ciphertext = algorithm->EncrypText(plaintext, key, iv);
        std::string decryptedtext = algorithm->DecrypText(ciphertext, key, iv);
        std::cout << "Plaintext : " << plaintext << std::endl;
        std::cout << "Ciphertext : ";
        for (unsigned char c : ciphertext) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        std::cout << std::endl;
        std::cout << "Decrypted text: " << decryptedtext << std::endl;

        if (plaintext == decryptedtext) {
            std::cout << "Test Passed: Decrypted text matches the original plaintext." << std::endl;
        }
        else {
            std::cout << "Test Failed: Decrypted text does not match the original plaintext." << std::endl;
        }
        auto end = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;
        std::time_t end_time = std::chrono::system_clock::to_time_t(end);

        std::cout << "finished computation at " << std::ctime(&end_time)
            << "elapsed time: " << elapsed_seconds.count() << "s"
            << '\n';
        std::cout << "**************************\n";
    }
}

int main() {
    TestAlgorithms();
    return 0;
}