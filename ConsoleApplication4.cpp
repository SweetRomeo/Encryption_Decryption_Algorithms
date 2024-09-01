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

template <typename AlgoType>
std::string getAlgorithmInfoString(AlgoType& algo) {
    // AlgoType nesnesini kopyalamak yerine referans olarak kullanıyoruz.
    Algorithm* algorithm = &algo;

    unsigned char key[AES_BLOCK_SIZE] = { 0 };
    unsigned char iv[AES_BLOCK_SIZE] = { 0 };

    auto start = std::chrono::system_clock::now();
    std::stringstream algoType;
    algorithm->initializeKey(key, iv);
    const std::type_info& typeInfo = typeid(*algorithm);
    algoType << typeInfo.name() << '\n';
    std::string algoTypeTemp = algoType.str().substr(6);
    std::stringstream algoInfoText;
    algoInfoText << "Algorithm Name :" << algoTypeTemp;
    std::string plainText = "Hello, World!";
    std::string cipherText = algorithm->EncrypText(plainText, key, iv);
    std::string decryptedText = algorithm->DecrypText(cipherText, key, iv);
    algoInfoText << "Plaintext : " << plainText << '\n';
    algoInfoText << "Ciphertext : ";
    for (unsigned char c : cipherText) {
        algoInfoText << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    algoInfoText << '\n';
    algoInfoText << "Decrypted text : " << decryptedText << '\n';

    if (plainText == decryptedText) {
        algoInfoText << "Test Passed: Decryption text matches the original plaintext." << '\n';
    }
    else {
        algoInfoText << "Test Failed: Decryption text does not match the original plaintext." << '\n';
    }

    auto end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    algoInfoText << "Finished computation at " << std::ctime(&end_time)
        << "Elapsed time : " << elapsed_seconds.count() << "s" << '\n';

    return algoInfoText.str();
}

HWND AesAlgorithmButton, SeedAlgorithmButton, RsaAlgorithmButton,
Cast5AlgorithmButton, CamelliaAlgorithmButton, DsaAlgorithmButton,
Chacha20AlgorithmButton, DhAlgorithmButton;

HWND hStaticText;  // Kalıcı metin göstermek için Static kontrol

std::wstring convertToWString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static WCHAR tempText[1000]; // Geçici metin tutmak için bir buffer

    // Algoritma nesnelerini static olarak tanımlıyoruz
    static Aes aes;
    static Seed seed;
    static Rsa rsa;
    static Cast5 cast5;
    static Camellia camellia;
    static Dsa dsa;
    static ChaCha20 chacha20;
    static Dh dh;
    static std::string buttonPressText;
    static std::wstring wideButtonPressText; // std::string'i std::wstring'e çevirme

    switch (uMsg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_COMMAND:
        // Button Press işlemleri
        switch (LOWORD(wParam)) {
        case 1:
            MessageBox(hwnd, L"AES Algorithm Service has started", L"AES", MB_OK | MB_ICONINFORMATION);
            SetWindowText(AesAlgorithmButton, L"Aes");
            buttonPressText = getAlgorithmInfoString(aes);
            break;
        case 2:
            MessageBox(hwnd, L"Seed Algorithm Service has started", L"Seed", MB_OK | MB_ICONINFORMATION);
            SetWindowText(SeedAlgorithmButton, L"Seed");
            buttonPressText = getAlgorithmInfoString(seed);
            break;
        case 3:
            MessageBox(hwnd, L"RSA Algorithm Service has started", L"RSA", MB_OK | MB_ICONINFORMATION);
            SetWindowText(RsaAlgorithmButton, L"Rsa");
            buttonPressText = getAlgorithmInfoString(rsa);
            break;
        case 4:
            MessageBox(hwnd, L"Cast5 Algorithm Service has started", L"Cast5", MB_OK | MB_ICONINFORMATION);
            SetWindowText(Cast5AlgorithmButton, L"Cast5");
            buttonPressText = getAlgorithmInfoString(cast5);
            break;
        case 5:
            MessageBox(hwnd, L"Camellia Algorithm Service has started", L"Camellia", MB_OK | MB_ICONINFORMATION);
            SetWindowText(CamelliaAlgorithmButton, L"Camellia");
            buttonPressText = getAlgorithmInfoString(camellia);
            break;
        case 6:
            MessageBox(hwnd, L"DSA Algorithm Service has started", L"DSA", MB_OK | MB_ICONINFORMATION);
            SetWindowText(DsaAlgorithmButton, L"Dsa");
            buttonPressText = getAlgorithmInfoString(dsa);
            break;
        case 7:
            MessageBox(hwnd, L"ChaCha20 Algorithm Service has started", L"ChaCha20", MB_OK | MB_ICONINFORMATION);
            SetWindowText(Chacha20AlgorithmButton, L"ChaCha20");
            buttonPressText = getAlgorithmInfoString(chacha20);
            break;
        case 8:
            MessageBox(hwnd, L"DH Algorithm Service has started", L"DH", MB_OK | MB_ICONINFORMATION);
            SetWindowText(DhAlgorithmButton, L"Dh");
            buttonPressText = getAlgorithmInfoString(dh);
            break;
        }
        // Metni geniş karakter setine dönüştür
        wideButtonPressText = convertToWString(buttonPressText);
        // Geçici buffer'a kopyala
        wcscpy_s(tempText, wideButtonPressText.c_str());
        // Static kontrol üzerinde kalıcı olarak metni güncelle
        SetWindowText(hStaticText, tempText);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // Bu kısımda `std::wstring` kullanıyoruz.
        std::wstring text = L"Hello, World!";
        TextOut(hdc, 50, 50, text.c_str(), text.size());

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

    hStaticText = CreateWindow(
        L"STATIC",
        L"Please select an Algorithm",  // Başlangıç metni
        WS_VISIBLE | WS_CHILD,
        200, 100, 800, 500,  // Bu kısmı arayüzde görmek istediğiniz yere göre ayarlayabilirsiniz
        hwnd,
        nullptr,
        hInstance,
        nullptr
    );

    //Mesaj döngüsü
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