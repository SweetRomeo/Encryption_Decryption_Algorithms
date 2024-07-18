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
#include <random>

void randomFill(std::string& text, int size) {
    std::string alphaBeth = "abcdefghijklmnqprstuvwxyz";
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(0, alphaBeth.size() - 1);

    for (int i = 0; i < size; ++i) {
        char randomChar = alphaBeth.at(dist(mt));
        text.push_back(randomChar);
    }
}

void TestAlgorithms() {
    std::vector<std::unique_ptr<Algorithm>> algorithms;
    algorithms.emplace_back(std::make_unique<Aes>());
    algorithms.emplace_back(std::make_unique<Seed>());
    algorithms.emplace_back(std::make_unique<Rsa>());
    algorithms.emplace_back(std::make_unique<Cast5>());
    algorithms.emplace_back(std::make_unique<Camellia>());
    algorithms.emplace_back(std::make_unique<Dsa>());
    algorithms.emplace_back(std::make_unique<ChaCha20>());
    algorithms.emplace_back(std::make_unique<Dh>());
    //algorithms.emplace_back(std::make_unique<Ecdsa>());
    //algorithms.emplace_back(std::make_unique<Idea>());
    //algorithms.emplace_back(std::make_unique<Blowfish>());

    unsigned char key[AES_BLOCK_SIZE] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };

    std::vector<std::pair<std::string, bool>> Algorithms = { { "RSA", false },{ "DSA", false },{ "DH", false },{ "Chacha20", true },
         { "Camellia", true }, { "DES", true }, { "RC4", true }, { "AES", true }, { "Seed", true }, {"Cast5", true } };

    for (const auto& algorithm : algorithms) {
        auto start = std::chrono::system_clock::now();
        std::stringstream algoType;
        algorithm->initializeKey(key, iv);

        const std::type_info& typeInfo = typeid(*algorithm);
        algoType << typeInfo.name() << std::endl;
        std::string algoTypeTemp = algoType.str();
        algoTypeTemp = algoTypeTemp.substr(6);
        algoTypeTemp.erase(std::remove_if(algoTypeTemp.begin(), algoTypeTemp.end(), ::isspace), algoTypeTemp.end());
        std::cout << "Algorithm Name : " << algoTypeTemp << '\n';
        for (auto& [AlgoName, isSimetric] : Algorithms) {
            if(AlgoName == algoTypeTemp)
            std::cout << "Algorithm Type : " << (isSimetric ? "Simetric" : "Asimetric") << '\n';
        }

        std::string plaintext;
        randomFill(plaintext, 100);
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