#pragma warning(disable : 4996)
#include "SecurityUtil.h"
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <cstring>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>

Algorithm::Algorithm()
{
    std::cout << "Algorithm ctor\n";
}

Algorithm::~Algorithm()
{
    std::cout << "Algorithm dtor\n";
}



SimetricAlgorithm::SimetricAlgorithm()
{
    std::cout << "SimetricAlgorithm ctor\n";
}

SimetricAlgorithm::~SimetricAlgorithm()
{
    std::cout << "SimetricAlgorithm dtor\n";
}

std::string Aes::EncrypText(const std::string& plaintext, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const
{
    AES_KEY encKey;
    AES_set_encrypt_key(key, 128, &encKey);

    // Giriþ metnini blok boyutuna tamamlamak için padding ekleyin
    int padding_required = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
    std::string padded_text = plaintext + std::string(padding_required, char(padding_required));

    // Þifreli metin için yeterli alan ayrýlýr
    std::string ciphertext(padded_text.size(), '\0');

    // Þifrelemeyi gerçekleþtir
    unsigned char temp_iv[AES_BLOCK_SIZE];  // CBC modu için IV'nin kopyasý
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt((unsigned char*)&padded_text[0], (unsigned char*)&ciphertext[0], padded_text.size(), &encKey, temp_iv, AES_ENCRYPT);

    return ciphertext;
}

std::string Aes::DecrypText(const std::string& ciphertext, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const 
{
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);

    std::string decryptedtext(ciphertext.size(), '\0');

    // Þifreyi çöz
    unsigned char temp_iv[AES_BLOCK_SIZE];  // CBC modu için IV'nin kopyasý
    memcpy(temp_iv, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt((unsigned char*)&ciphertext[0], (unsigned char*)&decryptedtext[0], ciphertext.size(), &dec_key, temp_iv, AES_DECRYPT);

    // Padding'i kaldýr
    int padding_len = decryptedtext.back();
    decryptedtext.resize(decryptedtext.size() - padding_len);

    return decryptedtext;
}

void Aes::EncrypFile(const std::string& inputFileName, const std::string& outputFileName, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) {
    std::ifstream inFile(inputFileName, std::ios::binary);
    if (!inFile.is_open()) {
        throw std::runtime_error("Unable to open input file for reading");
    }

    std::vector<unsigned char> content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    AES_KEY encryptKey;
    AES_set_encrypt_key(key, 128, &encryptKey);

    std::vector<unsigned char> cipherContent(content.size());
    int num = 0;
    unsigned char currentIV[AES_BLOCK_SIZE];
    memcpy(currentIV, iv, AES_BLOCK_SIZE);

    AES_cfb128_encrypt(content.data(), cipherContent.data(), content.size(), &encryptKey, currentIV, &num, AES_ENCRYPT);

    std::ofstream outFile(outputFileName, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("Unable to open output file for writing");
    }

    outFile.write(reinterpret_cast<char*>(cipherContent.data()), cipherContent.size());
    outFile.close();
}

// Dosya deþifreleme fonksiyonu
void Aes::DecrypFile(const std::string& inputFileName, const std::string& outputFileName, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) {
    std::ifstream inFile(inputFileName, std::ios::binary);
    if (!inFile.is_open()) {
        throw std::runtime_error("Unable to open input file for reading");
    }

    std::vector<unsigned char> content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    AES_KEY decryptKey;
    AES_set_decrypt_key(key, 128, &decryptKey);

    std::vector<unsigned char> plainContent(content.size());
    int num = 0;
    unsigned char currentIV[AES_BLOCK_SIZE];
    memcpy(currentIV, iv, AES_BLOCK_SIZE);

    AES_cfb128_encrypt(content.data(), plainContent.data(), content.size(), &decryptKey, currentIV, &num, AES_DECRYPT);

    std::ofstream outFile(outputFileName, std::ios::binary);
    if (!outFile.is_open()) {
        throw std::runtime_error("Unable to open output file for writing");
    }

    outFile.write(reinterpret_cast<char*>(plainContent.data()), plainContent.size());
    outFile.close();
}

void Aes::TextCryptionTest()
{
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    initializeKey(key, iv);

    std::string plainText = "This is a test text.";
    std::cout << "Plaintext : " << plainText << '\n';

    std::string cipherText = EncrypText(plainText, key, iv);
    std::cout << "Plaintext : ";
    for (auto& c : cipherText) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << c;
    }
    std::string decrpytedText = DecrypText(cipherText, key, iv);
    std::cout << "\nDecrypted Text : " << decrpytedText << '\n';
    if (plainText == decrpytedText) {
        std::cout << "Test Passed: Decrypted text matches the original plaintext.\n";
    }
    else {
        std::cout << "Test Failed: Decrypted text does not match the original plaintext.\n";
    }
}

void Aes::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE])
{
    if (!RAND_bytes(key, AES_BLOCK_SIZE) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
        throw std::runtime_error("Unable to generate key and IV");
    }
}

std::string Seed::EncrypText(const std::string& plainText, const unsigned char key[SEED_KEY_LENGTH], const unsigned char iv[SEED_BLOCK_SIZE])const  
{
    SEED_KEY_SCHEDULE encKey;
    SEED_set_key(key, &encKey);

    auto padding_required = SEED_BLOCK_SIZE - (plainText.size() % SEED_BLOCK_SIZE);
    std::string padded_text = plainText + std::string(padding_required, char(padding_required));

    std::string ciphertext(padded_text.size(), '\0');
    unsigned char temp_iv[SEED_BLOCK_SIZE];
    memcpy(temp_iv, iv, SEED_BLOCK_SIZE);
    SEED_cbc_encrypt((unsigned char*)&padded_text[0], (unsigned char*)&ciphertext[0], padded_text.size(), &encKey, temp_iv, 1);

    return ciphertext;
}

std::string Seed::DecrypText(const std::string& ciphertext, const unsigned char key[SEED_KEY_LENGTH], const unsigned char iv[SEED_BLOCK_SIZE])const
{
    SEED_KEY_SCHEDULE dec_key;
    SEED_set_key(key, &dec_key);

    std::string decryptedtext(ciphertext.size(), '\0');
    unsigned char temp_iv[SEED_BLOCK_SIZE];
    memcpy(temp_iv, iv, SEED_BLOCK_SIZE);
    SEED_cbc_encrypt((unsigned char*)&ciphertext[0], (unsigned char*)&decryptedtext[0], ciphertext.size(), &dec_key, temp_iv, 0);

    // Padding'i kaldýr
    int padding_len = decryptedtext.back();
    decryptedtext.resize(decryptedtext.size() - padding_len);

    return decryptedtext;
}

void Seed::initializeKey(unsigned char key[SEED_KEY_LENGTH], unsigned char iv[SEED_BLOCK_SIZE]) {
    if (!RAND_bytes(key, SEED_KEY_LENGTH)) {
        std::cerr << "Error generating random key" << std::endl;
    }
    if (!RAND_bytes(iv, SEED_BLOCK_SIZE)) {
        std::cerr << "Error generating random IV" << std::endl;
    }
}

void Blowfish::initializeKey(unsigned char key[16], unsigned char iv[8]) {
    if (!RAND_bytes(key, 16)) {
        std::cerr << "Error generating random key" << std::endl;
    }
    if (!RAND_bytes(iv, 8)) {
        std::cerr << "Error generating random IV" << std::endl;
    }
}

std::string Blowfish::EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[8]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + BF_BLOCK);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Blowfish::DecrypText(const std::string& ciphertext, const unsigned char key[16], const unsigned char iv[8]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

void Camellia::initializeKey(unsigned char key[CAMELLIA_BLOCK_SIZE], unsigned char iv[CAMELLIA_BLOCK_SIZE]) {
    if (!RAND_bytes(key, CAMELLIA_BLOCK_SIZE)) {
        std::cerr << "Error generating random key" << std::endl;
    }
    if (!RAND_bytes(iv, CAMELLIA_BLOCK_SIZE)) {
        std::cerr << "Error generating random IV" << std::endl;
    }
}

std::string Camellia::EncrypText(const std::string& plainText, const unsigned char key[CAMELLIA_BLOCK_SIZE], const unsigned char iv[CAMELLIA_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_camellia_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + CAMELLIA_BLOCK_SIZE);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Camellia::DecrypText(const std::string& ciphertext, const unsigned char key[CAMELLIA_BLOCK_SIZE], const unsigned char iv[CAMELLIA_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_camellia_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

void Idea::initializeKey(unsigned char key[IDEA_KEY_LENGTH], unsigned char iv[IDEA_KEY_LENGTH]) {
    if (!RAND_bytes(key, IDEA_KEY_LENGTH)) {
        std::cerr << "Error generating random key" << std::endl;
    }
    if (!RAND_bytes(iv, IDEA_KEY_LENGTH)) {
        std::cerr << "Error generating random IV" << std::endl;
    }
}

std::string Idea::EncrypText(const std::string& plainText, const unsigned char key[IDEA_KEY_LENGTH], const unsigned char iv[IDEA_KEY_LENGTH]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + IDEA_KEY_LENGTH);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Idea::DecrypText(const std::string& ciphertext, const unsigned char key[IDEA_KEY_LENGTH], const unsigned char iv[IDEA_KEY_LENGTH]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_idea_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

std::string Cast5::DecrypText(const std::string& cipherText, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK]) const {
    CAST_KEY decKey;
    CAST_set_key(&decKey, CAST_KEY_LENGTH, key);

    std::string decryptedText(cipherText.length(), '\0');
    unsigned char tempIv[CAST_BLOCK];
    memcpy(tempIv, iv, CAST_BLOCK);
    CAST_cbc_encrypt((unsigned char*)(&cipherText[0]), reinterpret_cast<unsigned char*>(&decryptedText[0]),
                     cipherText.length(), &decKey, tempIv, CAST_DECRYPT);
    int paddingLen = decryptedText.back();
    decryptedText.resize(decryptedText.size() - paddingLen);
    return decryptedText;
}

std::string Cast5::EncrypText(const std::string& plainText, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK]) const
{
    CAST_KEY encKey;
    CAST_set_key(&encKey, CAST_KEY_LENGTH, key);

    auto paddingRequired = CAST_BLOCK - (plainText.length() % CAST_BLOCK);
    std::string paddedText = plainText + std::string(paddingRequired, char(paddingRequired));

    std::string cipherText(paddedText.length(), '/0');
    unsigned char tempIv[CAST_BLOCK];
    memcpy(tempIv, iv, CAST_BLOCK);
    CAST_cbc_encrypt(reinterpret_cast<unsigned char*>(&paddedText[0]), reinterpret_cast<unsigned char*>(&cipherText[0]), 
                     paddedText.length(), &encKey, tempIv, CAST_ENCRYPT);

    return cipherText;
}

void Cast5::initializeKey(unsigned char key[CAST_KEY_LENGTH], unsigned char iv[CAST_BLOCK]) {
    RAND_bytes(key, CAST_KEY_LENGTH);
    //keyLength = CAST_KEY_LENGTH * 8;
    RAND_bytes(iv, CAST_BLOCK);
}

Rsa::Rsa() : rsa(nullptr), bne(nullptr) {}

Rsa::~Rsa() {
    if (rsa) {
        RSA_free(rsa);
    }
    if (bne) {
        BN_free(bne);
    }
}

void Rsa::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) {
    bne = BN_new();
    if (!BN_set_word(bne, e)) {
        std::cerr << "Error setting BIGNUM word" << std::endl;
        return;
    }

    rsa = RSA_new();
    if (!RSA_generate_key_ex(rsa, bits, bne, NULL)) {
        std::cerr << "Error generating RSA key" << std::endl;
        RSA_free(rsa);
        rsa = nullptr;
        return;
    }

    // Key and IV initialization are not needed for RSA, so this part is skipped.
}



std::string Rsa::EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    std::vector<unsigned char> encrypted(RSA_size(rsa));
    int result = RSA_public_encrypt(plainText.size(), reinterpret_cast<const unsigned char*>(plainText.c_str()), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        char err[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Error encrypting message: " << err << std::endl;
        return "";
    }

    return std::string(encrypted.begin(), encrypted.end());
}

std::string Rsa::DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    std::vector<unsigned char> decrypted(RSA_size(rsa));
    int result = RSA_private_decrypt(cipherText.size(), reinterpret_cast<const unsigned char*>(cipherText.c_str()), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        char err[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Error decrypting message: " << err << std::endl;
        return "";
    }

    return std::string(decrypted.begin(), decrypted.begin() + result);
}

Dsa::Dsa() {
    dsa = DSA_new();
    if (!dsa) {
        std::cerr << "Error creating DSA object" << std::endl;
    }
}

Dsa::~Dsa() {
    if (dsa) {
        DSA_free(dsa);
    }
}

void Dsa::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) {
    if (!RAND_bytes(key, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating random key" << std::endl;
    }
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating random IV" << std::endl;
    }
}

std::string Dsa::EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int len;
    int ciphertext_len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size()) != 1) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Dsa::DecrypText(const std::string& ciphertext, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int len;
    int plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

Dh::Dh() : dh(nullptr), pubKey(nullptr), privKey(nullptr), sharedKey(nullptr) {}

Dh::~Dh() {
    if (dh) {
        DH_free(dh);
    }
    if (pubKey) {
        BN_free(pubKey);
    }
    if (privKey) {
        BN_free(privKey);
    }
    if (sharedKey) {
        OPENSSL_free(sharedKey);
    }
}

void Dh::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) {
    dh = DH_new();
    if (!dh) {
        std::cerr << "Error creating DH structure" << std::endl;
        return;
    }

    if (!DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr)) {
        std::cerr << "Error generating DH parameters" << std::endl;
        DH_free(dh);
        dh = nullptr;
        return;
    }

    if (!DH_generate_key(dh)) {
        std::cerr << "Error generating DH key" << std::endl;
        DH_free(dh);
        dh = nullptr;
        return;
    }

    pubKey = BN_dup(DH_get0_pub_key(dh));
    privKey = BN_dup(DH_get0_priv_key(dh));

    // Generate a random IV
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        std::cerr << "Error generating random IV" << std::endl;
    }

    // For demonstration purposes, we'll generate a shared secret here
    // In a real application, you would exchange the public key with a peer
    BIGNUM* peerPubKey = BN_new();
    BN_rand(peerPubKey, 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    sharedKey = (unsigned char*)OPENSSL_malloc(DH_size(dh));
    if (!sharedKey) {
        std::cerr << "Error allocating memory for shared key" << std::endl;
        return;
    }

    int sharedKeyLen = DH_compute_key(sharedKey, peerPubKey, dh);
    if (sharedKeyLen == -1) {
        std::cerr << "Error computing shared key" << std::endl;
        OPENSSL_free(sharedKey);
        sharedKey = nullptr;
        return;
    }

    // Use the shared key as the encryption key
    std::copy(sharedKey, sharedKey + std::min(sharedKeyLen, AES_BLOCK_SIZE), key);

    BN_free(peerPubKey);
}

std::string Dh::EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Dh::DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(cipherText.size());
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

Ecdsa::Ecdsa() : eckey(nullptr) {}

Ecdsa::~Ecdsa() {
    if (eckey) {
        EC_KEY_free(eckey);
    }
}

void Ecdsa::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) {
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        std::cerr << "Error creating EC_KEY structure" << std::endl;
        return;
    }

    if (!EC_KEY_generate_key(eckey)) {
        std::cerr << "Error generating EC key" << std::endl;
        EC_KEY_free(eckey);
        eckey = nullptr;
        return;
    }

    // EC anahtarýný key[] ve iv[] dizilerine kopyalayýn (eðer gerekiyorsa)
    // Bu adým aslýnda ECDSA için gerekli deðil, burada yalnýzca sýnýfýn uyumunu saðlamak için eklenmiþtir.
    std::fill(key, key + 32, 0);  // 256 bit key
    std::fill(iv, iv + 16, 0);    // 128 bit IV
}

std::string Ecdsa::EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    if (!eckey) {
        std::cerr << "EC key is not initialized" << std::endl;
        return "";
    }

    unsigned char* sig = nullptr;
    unsigned int sig_len = 0;

    sig = (unsigned char*)OPENSSL_malloc(ECDSA_size(eckey));
    if (!sig) {
        std::cerr << "Error allocating memory for signature" << std::endl;
        return "";
    }

    if (!ECDSA_sign(0, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size(), sig, &sig_len, eckey)) {
        std::cerr << "Error signing message" << std::endl;
        OPENSSL_free(sig);
        return "";
    }

    std::string signature(reinterpret_cast<char*>(sig), sig_len);
    OPENSSL_free(sig);
    return signature;
}

std::string Ecdsa::DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const {
    if (!eckey) {
        std::cerr << "EC key is not initialized" << std::endl;
        return "";
    }

    int result = ECDSA_verify(0, reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size(),
        reinterpret_cast<const unsigned char*>(key), 32, eckey);

    if (result < 0) {
        std::cerr << "Error verifying signature" << std::endl;
        return "Verification Error";
    }

    return result == 1 ? "Verification Success" : "Verification Failure";
}

Ecdh::Ecdh() : eckey(nullptr), sharedKey(nullptr), sharedKeyLen(0) {}

Ecdh::~Ecdh() {
    if (eckey) {
        EC_KEY_free(eckey);
    }
    if (sharedKey) {
        OPENSSL_free(sharedKey);
    }
}

void Ecdh::initializeKey(unsigned char key[16], unsigned char iv[16]) {
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        std::cerr << "Error creating EC_KEY structure" << std::endl;
        return;
    }

    if (!EC_KEY_generate_key(eckey)) {
        std::cerr << "Error generating EC key" << std::endl;
        EC_KEY_free(eckey);
        eckey = nullptr;
        return;
    }

    // Generate a random IV
    if (!RAND_bytes(iv, 16)) {
        std::cerr << "Error generating random IV" << std::endl;
    }

    // For demonstration purposes, we'll generate a shared secret here
    // In a real application, you would exchange the public key with a peer
    EC_KEY* peerKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peerKey) {
        std::cerr << "Error creating peer EC_KEY structure" << std::endl;
        return;
    }

    if (!EC_KEY_generate_key(peerKey)) {
        std::cerr << "Error generating peer EC key" << std::endl;
        EC_KEY_free(peerKey);
        return;
    }

    const EC_POINT* peerPubKey = EC_KEY_get0_public_key(peerKey);
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    sharedKey = (unsigned char*)OPENSSL_malloc((EC_GROUP_get_degree(group) + 7) / 8);
    if (!sharedKey) {
        std::cerr << "Error allocating memory for shared key" << std::endl;
        EC_KEY_free(peerKey);
        return;
    }

    sharedKeyLen = ECDH_compute_key(sharedKey, (EC_GROUP_get_degree(group) + 7) / 8, peerPubKey, eckey, nullptr);
    if (sharedKeyLen <= 0) {
        std::cerr << "Error computing shared key" << std::endl;
        OPENSSL_free(sharedKey);
        sharedKey = nullptr;
        EC_KEY_free(peerKey);
        return;
    }

    // Use the shared key as the encryption key
    std::copy(sharedKey, sharedKey + std::min(sharedKeyLen, 16), key);
    EC_KEY_free(peerKey);
}

std::string Ecdh::EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[16]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + 16);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string Ecdh::DecrypText(const std::string& cipherText, const unsigned char key[16], const unsigned char iv[16]) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(cipherText.size());
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

void ChaCha20::initializeKey(unsigned char key[16], unsigned char iv[16]) {
    unsigned char tempKey[32];
    unsigned char tempIv[12];

    if (!RAND_bytes(tempKey, 32)) {
        std::cerr << "Error generating random key" << std::endl;
        return;
    }
    if (!RAND_bytes(tempIv, 12)) {
        std::cerr << "Error generating random IV" << std::endl;
        return;
    }

    std::copy(tempKey, tempKey + 16, key);
    std::copy(tempIv, tempIv + 12, iv);
}

std::string ChaCha20::EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[16]) const {
    unsigned char actualKey[32];
    unsigned char actualIv[12];

    std::copy(key, key + 16, actualKey);
    std::fill(actualKey + 16, actualKey + 32, 0); // Fill remaining bytes with 0

    std::copy(iv, iv + 12, actualIv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, actualKey, actualIv)) {
        std::cerr << "Error initializing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plainText.size() + 16);
    int len;
    int ciphertext_len;

    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        std::cerr << "Error during encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cerr << "Error finalizing encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

std::string ChaCha20::DecrypText(const std::string& cipherText, const unsigned char key[16], const unsigned char iv[16]) const {
    unsigned char actualKey[32];
    unsigned char actualIv[12];

    std::copy(key, key + 16, actualKey);
    std::fill(actualKey + 16, actualKey + 32, 0); // Fill remaining bytes with 0

    std::copy(iv, iv + 12, actualIv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context" << std::endl;
        return "";
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, actualKey, actualIv)) {
        std::cerr << "Error initializing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(cipherText.size() + 16);
    int len;
    int plaintext_len;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size())) {
        std::cerr << "Error during decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        std::cerr << "Error finalizing decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}