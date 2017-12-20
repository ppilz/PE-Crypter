#include <cstdint>
#include <cstring>
#include "Crypto.h"

/*
 * This class provides the policy based design pattern to serve multiple
 * methods of encryption and allows the addition of new encryption methods easily.
 * Template definition and implementation in Crypto.h
 *
 * Note: May switch to strategy pattern if a GUI is implemented as well to allow
 * policy selection at runtime.
*/


/*
 * Simple XOR encryption. Works with any key size.
 */
void CryptPolicyXOR::encrypt(DATA *data, uint32_t key[4], int keylen) const
{
	for (int i = 0; i < data->size; i++)
		data->image[i] = data->image[i] ^ key[i % keylen];
}

/*
 * XOR decryption == XOR encryption
*/
void CryptPolicyXOR::decrypt(DATA *data, uint32_t key[4], int keylen) const
{
	encrypt(data, key, keylen);
}

/*
 * Adapted version of the XTEA algorithm given at https://en.wikipedia.org/wiki/XTEA
 */
void CryptPolicyXTEA::encrypt(DATA *data, uint32_t key[4], int keylen) const
{
	int n_blocks = data->size / XTEA_BLOCK_SIZE; // Calculate number of blocks
	if (data->size % XTEA_BLOCK_SIZE != 0)
		++n_blocks; // Fix alignment

	for (int j = 0; j<n_blocks; j++) {
		unsigned char block[XTEA_BLOCK_SIZE];
		memcpy(block, data->image + (j*XTEA_BLOCK_SIZE), XTEA_BLOCK_SIZE);

		// Set up the 64 data bits
		uint32_t v0, v1;
		memcpy(&v0, block, 4);
		memcpy(&v1, block + 4, 4);

		// Perform the encryption
		uint32_t sum = 0, delta = 0x9E3779B9;
		unsigned int i;
		for (i = 0; i < XTEA_ROUNDS; i++) {
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
			sum += delta;
			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
		}
		memcpy(data->image, &v0, 4);
		memcpy(data->image + 4, &v1, 4);
	}
}

/*
 * Adapted version of the XTEA algorithm given at https://en.wikipedia.org/wiki/XTEA
 */
void CryptPolicyXTEA::decrypt(DATA *data, uint32_t key[4], int keylen) const
{
	int n_blocks = data->size / XTEA_BLOCK_SIZE; // Calculate number of blocks
	if (data->size % XTEA_BLOCK_SIZE != 0)
		++n_blocks; // Fix alignment

	for (int j = 0; j<n_blocks; j++) {
		unsigned char block[XTEA_BLOCK_SIZE];
		memcpy(block, data->image + (j*XTEA_BLOCK_SIZE), XTEA_BLOCK_SIZE);

		// Set up the 64 data bits
		uint32_t v0, v1;
		memcpy(&v0, block, 4);
		memcpy(&v1, block + 4, 4);

		// Perform the encryption
		uint32_t sum = 0, delta = 0x9E3779B9;
		unsigned int i;
		for (i = 0; i < XTEA_ROUNDS; i++) {
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
			sum -= delta;
			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
		}
		memcpy(data->image, &v0, 4);
		memcpy(data->image + 4, &v1, 4);
	}
}