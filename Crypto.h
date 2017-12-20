#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <stdlib.h>

#define XTEA_BLOCK_SIZE 8
#define XTEA_ROUNDS 32

/*
 * image string holds the executable
 * size holds the size of the executable
 */
typedef struct {
	char* image;
	//std::streampos size;
	unsigned int size;
} DATA;


/*
TODO: Use variadic templates to support different amounts of arguments
and in consequence allow more flexibility for the crypto algorithms ???

struct Crypto : private CryptPolicy {
This constructor takes a variable number of arguments and forwards them to the
base class.
template<typename... Ts> Crypto(Ts&&... ts) : CryptPolicy(std::forward<Ts>(ts)...) {}
};
*/

template <typename CryptPolicy>
class Crypto : private CryptPolicy
{
public:
	void doCrypt(DATA *data, uint32_t key[4], int keylen) const;
	void doDecrypt(DATA *data, uint32_t key[4], int keylen) const;
};

template <typename CryptPolicy>
void Crypto<CryptPolicy>::doCrypt(DATA *data, uint32_t key[4], int keylen) const
{
	// Apply the given policy
	CryptPolicy::encrypt(data, key, keylen);
}

template <typename CryptPolicy>
void Crypto<CryptPolicy>::doDecrypt(DATA *data, uint32_t key[4], int keylen) const
{
	// Apply the given policy
	CryptPolicy::decrypt(data, key, keylen);
}


class CryptPolicyXOR
{
protected:
	void encrypt(DATA *data, uint32_t key[4], int keylen) const;
	void decrypt(DATA *data, uint32_t key[4], int keylen) const;
};

class CryptPolicyXTEA
{
protected:
	void encrypt(DATA *data, uint32_t key[4], int keylen) const;
	void decrypt(DATA *data, uint32_t key[4], int keylen) const;
};

#endif // !_CRYPTO_H_