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

std::string AES::EncrypText(const std::string& plaintext, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const
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

std::string AES::DecrypText(const std::string& ciphertext, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const 
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

void AES::TextCryptionTest()
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

void AES::initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE])
{
    RAND_bytes(key, AES_BLOCK_SIZE);
    RAND_bytes(iv, AES_BLOCK_SIZE);
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



