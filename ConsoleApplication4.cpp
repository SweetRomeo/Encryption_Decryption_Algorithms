﻿#pragma warning(disable : 4996)

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
#include <fstream>
#include <thread>
#include <windows.h>

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
//
//void EncrypFile(const std::string& inputFileName, const std::string& outputFileName, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) {
//    std::ifstream inFile(inputFileName, std::ios::binary);
//    if (!inFile.is_open()) {
//        throw std::runtime_error("Unable to open input file for reading");
//    }
//
//    std::vector<unsigned char> content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
//    inFile.close();
//
//    AES_KEY encryptKey;
//    AES_set_encrypt_key(key, 128, &encryptKey);
//
//    std::vector<unsigned char> cipherContent(content.size());
//    int num = 0;
//    unsigned char currentIV[AES_BLOCK_SIZE];
//    memcpy(currentIV, iv, AES_BLOCK_SIZE);
//
//    AES_cfb128_encrypt(content.data(), cipherContent.data(), content.size(), &encryptKey, currentIV, &num, AES_ENCRYPT);
//
//    std::ofstream outFile(outputFileName, std::ios::binary);
//    if (!outFile.is_open()) {
//        throw std::runtime_error("Unable to open output file for writing");
//    }
//
//    outFile.write(reinterpret_cast<char*>(cipherContent.data()), cipherContent.size());
//    outFile.close();
//}
//
//// Dosya deşifreleme fonksiyonu
//void DecrypFile(const std::string& inputFileName, const std::string& outputFileName, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) {
//    std::ifstream inFile(inputFileName, std::ios::binary);
//    if (!inFile.is_open()) {
//        throw std::runtime_error("Unable to open input file for reading");
//    }
//
//    std::vector<unsigned char> content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
//    inFile.close();
//
//    AES_KEY decryptKey;
//    AES_set_decrypt_key(key, 128, &decryptKey);
//
//    std::vector<unsigned char> plainContent(content.size());
//    int num = 0;
//    unsigned char currentIV[AES_BLOCK_SIZE];
//    memcpy(currentIV, iv, AES_BLOCK_SIZE);
//
//    AES_cfb128_encrypt(content.data(), plainContent.data(), content.size(), &decryptKey, currentIV, &num, AES_DECRYPT);
//
//    std::ofstream outFile(outputFileName, std::ios::binary);
//    if (!outFile.is_open()) {
//        throw std::runtime_error("Unable to open output file for writing");
//    }
//
//    outFile.write(reinterpret_cast<char*>(plainContent.data()), plainContent.size());
//    outFile.close();
//}

HWND AesAlgorithmButton, SeedAlgorithmButton, RsaAlgorithmButton,
     Cast5AlgorithmButton, CamelliaAlgorithmButton, DsaAlgorithmButton,
     Chacha20AlgorithmButton, DhAlgorithmButton;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case 1:
                MessageBox(hwnd, L"AES Algorithm Service has started", L"AES", MB_OK | MB_ICONINFORMATION);
                SetWindowText(AesAlgorithmButton, L"Aes");
                SetFocus(AesAlgorithmButton);
                break;
            case 2:
                MessageBox(hwnd, L"Seed Algorithm Service has started", L"Seed", MB_OK | MB_ICONINFORMATION);
                SetWindowText(SeedAlgorithmButton, L"Seed");
                SetFocus(SeedAlgorithmButton);
                break;
            case 3:
                MessageBox(hwnd, L"Rsa Algorithm Service has started", L"RSA", MB_OK | MB_ICONINFORMATION);
                SetWindowText(RsaAlgorithmButton, L"Rsa");
                SetFocus(RsaAlgorithmButton);
                break;
            case 4:
                MessageBox(hwnd, L"Cast5 Algorithm Service has started", L"Cast5", MB_OK | MB_ICONINFORMATION);
                SetWindowText(Cast5AlgorithmButton, L"Cast5");
                SetFocus(Cast5AlgorithmButton);
                break;
            case 5:
                MessageBox(hwnd, L"Camellia Algorithm Service has started", L"Camellia", MB_OK | MB_ICONINFORMATION);
                SetWindowText(CamelliaAlgorithmButton, L"Camellia");
                SetFocus(CamelliaAlgorithmButton);
                break;
            case 6:
                MessageBox(hwnd, L"Dsa Algorithm Service has started", L"DSA", MB_OK | MB_ICONINFORMATION);
                SetWindowText(DsaAlgorithmButton, L"Dsa");
                SetFocus(DsaAlgorithmButton);
                break;
            case 7:
                MessageBox(hwnd, L"Chacha20 Algorithm Service has started", L"Chacha20", MB_OK | MB_ICONINFORMATION);
                SetWindowText(Chacha20AlgorithmButton, L"Chacha20");
                SetFocus(Chacha20AlgorithmButton);
                break;
            case 8:
                MessageBox(hwnd, L"Dh Algorithm Service has started", L"Dh", MB_OK | MB_ICONINFORMATION);
                SetWindowText(DhAlgorithmButton, L"Dh");
                SetFocus(DhAlgorithmButton);
                break;
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        std::string text = "Hello, World!";
        TextOut(hdc, 50, 50, reinterpret_cast<LPCWSTR>(text.c_str()), text.size());

        EndPaint(hwnd, &ps);
    }
                 return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CreateWindowTest()
{
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    LPCWSTR CLASS_NAME = L"Sample Window Class";

    WNDCLASS wc = {};

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0,                              // Ekstra pencere stilleri
        CLASS_NAME,                     // Pencere sınıfı adı
        L"Encryption Algorithm Test Application",          // Pencere başlığı
        WS_OVERLAPPEDWINDOW,            // Pencere stili

        // Pencere boyutu ve pozisyonu
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,

        nullptr,       // Ebeveyn penceresi
        nullptr,       // Menü
        hInstance,  // Uygulama instance'ı
        nullptr        // Ekstra pencere verisi
    );

    if (hwnd == nullptr) {
        return;
    }

    ShowWindow(hwnd, SW_SHOW);

    //Create Buttons

    AesAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Aes",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 100, 100, 30,
        hwnd,
        (HMENU)1,  // Buton 1'in ID'si
        hInstance,
        nullptr
    );

    SeedAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Seed",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 140, 100, 30,
        hwnd,
        (HMENU)2,  // Buton 2'in ID'si
        hInstance,
        nullptr
    );
        
    RsaAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Rsa",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 180, 100, 30,
        hwnd,
        (HMENU)3,  // Buton 3'in ID'si
        hInstance,
        nullptr
    );
    
    Cast5AlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Cast5",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 220, 100, 30,
        hwnd,
        (HMENU)4,  // Buton 4'in ID'si
        hInstance,
        nullptr
    ); 
    
    CamelliaAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Camellia",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 260, 100, 30,
        hwnd,
        (HMENU)5,  // Buton 5'in ID'si
        hInstance,
        nullptr
    ); 
    
    DsaAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Dsa",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 300, 100, 30,
        hwnd,
        (HMENU)6,  // Buton 6'in ID'si
        hInstance,
        nullptr
    );
        
    Chacha20AlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Chacha20",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 340, 100, 30,
        hwnd,
        (HMENU)7,  // Buton 7'in ID'si
        hInstance,
        nullptr
    ); 
    
    DhAlgorithmButton = CreateWindow(
        L"BUTTON",
        L"Dh",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 380, 100, 30,
        hwnd,
        (HMENU)8,  // Buton 8'in ID'si
        hInstance,
        nullptr
    );

    // Mesaj döngüsü
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return;
}

int main() {
    CreateWindowTest();
    return 0;
}