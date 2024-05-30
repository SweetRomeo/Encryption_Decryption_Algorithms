#pragma once
#include <string>
#include <openssl/cast.h>
#include <openssl/aes.h>
#include <openssl/seed.h>
#include <openssl/rsa.h>
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/idea.h>
#include <openssl/dsa.h>

const int IDEA_BLOCK_SIZE = 8;   // 64 bit blok boyutu


class Algorithm {
public:
	Algorithm();
	virtual ~Algorithm();
	virtual std::string EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[16]) const = 0;
	virtual std::string DecrypText(const std::string& cipherText, const unsigned char key[16], const unsigned char iv[16]) const = 0;
	virtual void initializeKey(unsigned char key[16], unsigned char iv[16]) = 0;
	//virtual void EncrypFile(/*Parametreler*/);
	//virtual void DecrypFile(/*Parametreler*/);
protected:
	decltype(auto) calculateAlgorithmEfficiency();
};

class SimetricAlgorithm : public Algorithm {
public:
	SimetricAlgorithm();
	virtual ~SimetricAlgorithm();
	virtual std::string EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[16]) const override = 0;
	virtual std::string DecrypText(const std::string& cipherText, const unsigned char key[16], const unsigned char iv[16]) const override = 0;
	virtual void initializeKey(unsigned char key[16], unsigned char iv[16]) = 0;
};

class AsimetricAlgorithm : public Algorithm {
public:
	AsimetricAlgorithm() = default;
	virtual ~AsimetricAlgorithm() override = default;
	virtual std::string EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[16]) const override = 0;
	virtual std::string DecrypText(const std::string& cipherText, const unsigned char key[16], const unsigned char iv[16]) const override = 0;
	virtual void initializeKey(unsigned char key[16], unsigned char iv[16]) = 0;
};

class AES : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	void TextCryptionTest();
	void initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE])override;
};

class Seed : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[SEED_KEY_LENGTH], const unsigned char iv[SEED_BLOCK_SIZE])const final;
	std::string DecrypText(const std::string& ciphertext, const unsigned char key[SEED_KEY_LENGTH], const unsigned char iv[SEED_BLOCK_SIZE])const final;
	void initializeKey(unsigned char key[SEED_BLOCK_SIZE], unsigned char iv[SEED_BLOCK_SIZE])override;
};

class Blowfish : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[16], const unsigned char iv[8]) const final;
	std::string DecrypText(const std::string& ciphertext, const unsigned char key[16], const unsigned char iv[8]) const final;
	void initializeKey(unsigned char key[16], unsigned char iv[8]) override;
};

class Camellia : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[CAMELLIA_BLOCK_SIZE], const unsigned char iv[CAMELLIA_BLOCK_SIZE]) const final;
	std::string DecrypText(const std::string& ciphertext, const unsigned char key[CAMELLIA_BLOCK_SIZE], const unsigned char iv[CAMELLIA_BLOCK_SIZE]) const final;
	void initializeKey(unsigned char key[CAMELLIA_BLOCK_SIZE], unsigned char iv[CAMELLIA_BLOCK_SIZE]) override;
};

class Cast5 : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK]) const override;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[CAST_KEY_LENGTH], const unsigned char iv[CAST_BLOCK]) const override;
	void initializeKey(unsigned char key[CAST_KEY_LENGTH], unsigned char iv[CAST_BLOCK])override;
};

class Idea : public SimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[IDEA_KEY_LENGTH], const unsigned char iv[IDEA_KEY_LENGTH]) const final;
	std::string DecrypText(const std::string& ciphertext, const unsigned char key[IDEA_KEY_LENGTH], const unsigned char iv[IDEA_KEY_LENGTH]) const final;
	void initializeKey(unsigned char key[IDEA_KEY_LENGTH], unsigned char iv[IDEA_KEY_LENGTH]) override;
};

class Rsa : public AsimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	void initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) override;
	Rsa();
	~Rsa();
private:
	RSA* rsa;
	BIGNUM* bne;
	int bits = 2048;
	unsigned long e = RSA_F4;
};

class Dsa : public AsimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	Dsa();
	~Dsa();
	void initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) override;
private:
	DSA* dsa;
};

class Dh : public AsimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE])const final;
	void initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) override;
	Dh();
	~Dh();
private:
	DH* dh;
	BIGNUM* pubKey;
	BIGNUM* privKey;
	unsigned char* sharedKey;
};

class Ecdsa : public AsimetricAlgorithm {
public:
	std::string EncrypText(const std::string& plainText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const final;
	std::string DecrypText(const std::string& cipherText, const unsigned char key[AES_BLOCK_SIZE], const unsigned char iv[AES_BLOCK_SIZE]) const final;
	void initializeKey(unsigned char key[AES_BLOCK_SIZE], unsigned char iv[AES_BLOCK_SIZE]) override;
	Ecdsa();
	~Ecdsa();
private:
	EC_KEY* eckey;
};