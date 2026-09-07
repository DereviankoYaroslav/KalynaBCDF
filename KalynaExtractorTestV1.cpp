#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <bitset>
#include <windows.h>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cmath> 

#include "params.h"

//Kalyna
#include "kalyna.h"
#include "transformations.h"
#include "tables.c"

using namespace std;
#pragma warning(disable:4996)

uint8_t buf[64];
uint8_t dest[16000000];

void print(
	int data_len,
	uint8_t data[]
);

void print64(
	int data_size,
	uint64_t data[]
);

std::vector<uint8_t> ReadAllBytes(
	char* filePath
);

void WriteAllBytes(
	const std::string& filePath,
	const std::vector<uint8_t>& data
);

uint8_t getBit(
	const uint8_t* src,
	size_t bit
);

void setBit(
	uint8_t* dest,
	size_t bit,
	uint8_t value
);

void incGamma(
	uint8_t* gamma,
	size_t len
);

void movBits(
	uint8_t* dest,
	size_t dest_bit,
	const uint8_t* src,
	size_t src_bit,
	size_t src_bits
);

size_t padded(
	uint8_t* dest,
	const uint8_t* src,
	size_t src_len_bits,
	size_t nb
);

void createGamma(
	uint8_t* IV,
	kalyna_t* ctx,
	uint8_t* gamma
);

int ctrEncrypt(
	const uint8_t* M,
	size_t M_bitlen,
	uint8_t* gamma,
	uint8_t* ctr,
	size_t gamma_offset_bit,
	kalyna_t* ctx,
	uint8_t* ciphertext
);

void CTRMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	uint8_t* IV,
	uint8_t* M,
	size_t M_bitlen,
	const char* inFile,
	const char* outFile
);

void cfbEncrypt(
	const uint8_t* M,
	size_t M_bitlen,
	size_t q,
	uint8_t* gamma,
	kalyna_t* ctx,
	uint8_t* chiphertext
);

void CFBMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	uint8_t* IV,
	size_t q,
	uint8_t* M,
	size_t M_bitlen,
	const char* inFile,
	const char* outFile
);

void CMACMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	size_t q,
	uint8_t* M,
	size_t M_bitlen
);

void BlockCipherDFMode(
	size_t nb,
	size_t nk,
	uint8_t* M,
	size_t M_bitlen
);

int main()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	size_t nb, nk;


	//CTR MODE
	//(128, 128)
	nb = 2;
	nk = 2;

	uint8_t key22CTR[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	uint8_t IV_CTR[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	uint8_t M_CTR[41] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };


	//CTRMode(nb, nk, key22CTR, IV_CTR, NULL, 0, "rdseedSeq1.dat", "resultingCTRFile.dat");

	//printf("dest CTR = \n");
	//print(128, dest);

	//(256, 256)

	/*nb = 4;
	nk = 4;

	uint8_t key44CTR[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	uint8_t IV_44CTR[32] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};

	uint8_t M_CTR[41] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };

	CTRMode(nb, nk, key44CTR, IV_44CTR, NULL, 0, "rdseedSeq1.dat", "resultingCTRFile(256,256).dat");

	printf("dest CTR = \n");
	print(256, dest); */

	//(512, 512)
	/*nb = 8;
	nk = 8;

	uint8_t key88CTR[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};

	uint8_t IV_88CTR[64] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F
	};

	uint8_t M_CTR[41] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };

	CTRMode(nb, nk, key88CTR, IV_88CTR, NULL, 0, "rdseedSeq1.dat", "resultingCTRFile(512,512).dat");

	printf("dest CTR = \n");
	print(512, dest); */


	//CFB MODE
	//(128, 128)
	nb = 2;
	nk = 2;

	uint8_t key22CFB[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	uint8_t IV_CFB[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	uint8_t M_CFB[48] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };

	//CFBMode(nb, nk, key22CFB, IV_CFB, nb * 64, NULL, 0, "rdseedSeq1.dat", "resultingCFBFile.dat");

	//printf("dest CFB = \n");
	//print(128, dest);

	//(256, 256)
	/*nb = 4;
	nk = 4;

	uint8_t key44CFB[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	uint8_t IV_44CFB[32] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};

	uint8_t M_CFB[41] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };

	CFBMode(nb, nk, key44CFB, IV_44CFB, nb * 64, NULL, 0, "rdseedSeq1.dat", "resultingCFBFile(256,256).dat");

	printf("dest CFB = \n");
	print(256, dest); */


	//(512, 512)
	/*nb = 8;
	nk = 8;

	uint8_t key88CFB[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};

	uint8_t IV_88CFB[64] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
		0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F
	};

	uint8_t M_CFB[41] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };

	CFBMode(nb, nk, key88CFB, IV_88CFB, nb * 64, NULL, 0, "rdseedSeq1.dat", "resultingCFBFile(512,512).dat");

	printf("dest CFB = \n");
	print(512, dest); */

	//CMAC
	nb = 2;
	nk = 2;

	uint8_t M_CMAC[48] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };


	//CMACMode(nb, nk, key22CTR, nb * 64, M_CMAC, 48 * 8);

	//printf("dest CMAC = \n");
	//print(128, dest);

	//Block_cipher_df
	nb = 2;
	nk = 2;

	uint8_t M_Block_cipher_df[48] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
						 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
						 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F };


	BlockCipherDFMode(nb, nk, M_Block_cipher_df, 48 * 8);

	return 0;
}

/**
 * Виведення в консоль масиву октетів у HEX вигляді
 *
 * @param data_len - довжина даних у бітах
 * @paran data - масив октетів
 */
void print(int data_len, uint8_t data[])
{
	int i = 0;
	int data_size = data_len / BITS_IN_BYTE;
	for (i = 0; i < data_size; i++)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X ", (unsigned int)data[i]);
		if (!((i + 1) % 16)) printf("\n");
	};
	if (data_len % BITS_IN_BYTE != 0)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X ", (unsigned int)((data[i]) & (~((1 << (BITS_IN_BYTE - (data_len % BITS_IN_BYTE))) - 1))));
		if (!((i + 1) % 16)) printf("\n");
	};
	printf("\n");
};

void print64(int data_size, uint64_t data[])
{
	int i;
	uint8_t* tmp = (uint8_t*)data;
	for (i = 0; i < data_size * 8; i++)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X ", (unsigned int)tmp[i]);
		if (!((i + 1) % 16)) printf("\n");
	};
	printf("\n");
};

void createGamma(
	uint8_t* IV,
	kalyna_t* ctx,
	uint8_t* gamma
)
{
	KalynaEncipher((uint64_t*)IV, ctx, (uint64_t*)gamma);
}

int ctrEncrypt(
	const uint8_t* M,
	size_t M_bitlen,
	uint8_t* gamma,
	uint8_t* ctr,
	size_t gamma_offset_bit,
	kalyna_t* ctx,
	uint8_t* ciphertext
)
{
	uint8_t block[64];
	size_t block_size = ctx->nb * 8;
	memcpy(block, ctr, block_size);

	size_t gamma_offset = gamma_offset_bit / 8;
	size_t gamma_rest = gamma_offset_bit % 8;

	size_t bit_in_M = 0;
	size_t M_end_bit = M_bitlen;

	size_t gamma_bit = gamma_offset_bit;
	size_t gamma_end_bit = block_size * 8;

	for (; gamma_bit < gamma_end_bit && bit_in_M < M_end_bit; gamma_bit++, bit_in_M++)
	{
		uint8_t bit_from_gamma = getBit(gamma, gamma_bit);
		uint8_t bit_from_M = getBit(M, bit_in_M);
		setBit(ciphertext, bit_in_M, bit_from_M ^ bit_from_gamma);
	}
	if (gamma_bit == gamma_end_bit)
	{
		incGamma(ctr, block_size / 2);
		/*printf("ctr iter = \n");
		print(128, feed);*/

		memcpy(block, ctr, block_size / 2);
		KalynaEncipher((uint64_t*)block, ctx, (uint64_t*)gamma);
		/*printf("GAMMA iter = \n");
		print(128, gamma);*/

		gamma_bit = 0;
	}
	for (; bit_in_M < M_end_bit; bit_in_M++, gamma_bit++)
	{
		if (gamma_bit == gamma_end_bit)
		{
			incGamma(ctr, block_size / 2);
			/*printf("ctr iter = \n");
			print(128, ctr);*/

			memcpy(block, ctr, block_size / 2);
			KalynaEncipher((uint64_t*)block, ctx, (uint64_t*)gamma);
			/*printf("GAMMA iter = \n");
			print(128, gamma);*/

			gamma_bit = 0;
		}
		uint8_t bit_from_gamma = getBit(gamma, gamma_bit);
		uint8_t bit_from_M = getBit(M, bit_in_M);
		setBit(ciphertext, bit_in_M, bit_from_M ^ bit_from_gamma);
	}


	size_t M_len_full_bytes = (M_bitlen + 7) / 8 * 8;

	size_t i;
	for (i = M_bitlen; i < M_len_full_bytes; i++)
	{
		setBit(ciphertext, i, 0);
	}

	return (gamma_offset_bit + M_bitlen) % (block_size * 8);
}

void cfbEncrypt(
	const uint8_t* M,
	size_t M_bitlen,
	size_t q,
	uint8_t* gamma,
	kalyna_t* ctx,
	uint8_t* chiphertext
)
{

	size_t block_size = ctx->nb * 8;
	size_t block_bitlen = ctx->nb * 64;

	uint8_t gamma_iter[64];
	memcpy(gamma_iter, gamma, block_size);

	size_t bit_in_M = 0;

	size_t gamma_bit = block_bitlen - q;
	size_t gamma_end_bit = block_bitlen;

	size_t blocks_in_M = M_bitlen / q;
	size_t not_full_block_bits = M_bitlen % q;

	size_t i, j;
	for (i = 0; i < blocks_in_M; i++)
	{

		for (j = 0; j < q; j++)
		{
			uint8_t bit_from_gamma = getBit(gamma_iter, gamma_bit + j);
			uint8_t bit_from_M = getBit(M, bit_in_M + j);
			setBit(chiphertext, bit_in_M + j, bit_from_M ^ bit_from_gamma);
			setBit(gamma_iter, gamma_bit + j, bit_from_M ^ bit_from_gamma);

		}
		bit_in_M += j;

		KalynaEncipher((uint64_t*)gamma_iter, ctx, (uint64_t*)gamma_iter);
	}

	gamma_bit = gamma_end_bit - not_full_block_bits;
	if (not_full_block_bits) {
		for (j = 0; j < not_full_block_bits; j++)
		{
			uint8_t bit_from_gamma = getBit(gamma_iter, gamma_bit + j);
			uint8_t bit_from_M = getBit(M, bit_in_M + j);
			setBit(chiphertext, bit_in_M + j, bit_from_M ^ bit_from_gamma);
		}
		for (j = not_full_block_bits; j < 8; j++)
		{
			setBit(chiphertext, bit_in_M + j, 0);
		}
	}
}

int CMAC(
	const uint8_t* M,
	size_t M_bitlen,
	size_t q,
	kalyna_t* ctx,
	uint8_t* cmac
)
{
	int res = 0;
	size_t block_size = ctx->nb * 8;
	size_t block_bitlen = ctx->nb * 64;

	size_t temp_bitlen = (M_bitlen + block_bitlen - 1) / block_bitlen * block_bitlen;
	size_t temp_size = temp_bitlen / 8;
	uint8_t* temp = (uint8_t*)malloc(temp_size);
	res = temp != 0 ? 0 : 1;
	if (res == 0)
	{
		padded(temp, M, M_bitlen, ctx->nb);
		uint8_t C[64] = { 0 }, K_sigma[64] = { 0 };
		if (temp_bitlen != M_bitlen)
		{
			K_sigma[0] = 1;
		}
		KalynaEncipher((uint64_t*)K_sigma, ctx, (uint64_t*)K_sigma);


		size_t blocks = temp_size / block_size, i, j;
		for (i = 0; i < blocks - 1; i++)
		{
			for (j = 0; j < block_size; j++)
			{
				C[j] ^= temp[i * block_size + j];
			}
			KalynaEncipher((uint64_t*)C, ctx, (uint64_t*)C);

		}
		for (j = 0; j < block_size; j++)
		{
			C[j] ^= temp[i * block_size + j] ^ K_sigma[j];
		}
		KalynaEncipher((uint64_t*)C, ctx, (uint64_t*)C);
		memcpy(cmac, C, q / 8);
		free(temp);
	}
	return res;
}

void u32_to_bytes(unsigned char* out, uint32_t in)
{
	out[0] = (unsigned char)(in >> 24);
	out[1] = (unsigned char)(in >> 16);
	out[2] = (unsigned char)(in >> 8);
	out[3] = (unsigned char)in;
}

void BCC(
	kalyna_t* ctx,
	const uint8_t* data,
	size_t data_bitlen,
	size_t outlen,
	uint8_t* dest
)
{
	uint8_t* chaining_value = (uint8_t*)malloc(outlen / 8);
	uint8_t* input_block = (uint8_t*)malloc(outlen / 8);
	memset(chaining_value, 0, outlen / 8);

	size_t n = data_bitlen / outlen;
	printf("n = %d", n);

	printf("ch val = \n");
	print(outlen, chaining_value);

	printf("data = \n");
	print(data_bitlen, (uint8_t*)data);

	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < outlen / 8; j++) {
			std::cout << "i =  " << i << "outlen / 8 = " << outlen / 8 << endl;
			input_block[j] = chaining_value[j] ^ data[j];
			std::cout << "input block val is " << endl;
			printf("0x%02x\n", input_block[j]);
			std::cout << "chaining_value val is " << endl;
			printf("0x%02x\n", chaining_value[j]);
			std::cout << "data val is " << endl;
			printf("0x%02x\n", data[j]);
		}
		data += outlen / 8;
		printf("input_block = \n");
		print(outlen, input_block);
		KalynaEncipher((uint64_t*)input_block, ctx, (uint64_t*)chaining_value);
		printf("chaining_value = \n");
		print(outlen, chaining_value);
	}

	memcpy(dest, chaining_value, outlen / 8);
	printf("chaining_value = \n");
	print(outlen, chaining_value);
}

int block_cipher_df(
	const uint8_t* input_string,
	size_t input_len,
	size_t block_bitlen,
	uint32_t no_of_bits_to_return,
	uint8_t* requested_bits
)
{
	if (no_of_bits_to_return > MAX_NUMBER_OF_BITS) {
		return 1;
	}

	kalyna_t* ctx = KalynaInit(block_bitlen, no_of_bits_to_return);

	size_t block_size = ctx->nb * 8;

	// step 2
	uint8_t L[4];
	u32_to_bytes(L, input_len / 8);

	// step 3
	uint8_t N[4];
	u32_to_bytes(N, no_of_bits_to_return / 8);

	// step 4
	size_t concat_len = 4 + 4 + (input_len / 8) + 1;
	uint8_t* S = (uint8_t*)malloc(concat_len);
	uint8_t val[1] = { 0x80 };

	memcpy(S, L, 4);
	memcpy(S + 4, N, 4);
	memcpy(S + 8, input_string, (input_len / 8));
	memcpy(S + 8 + (input_len / 8), val, 1);

	printf("S = \n");
	print(concat_len * 8, S);

	//step 5
	size_t padding = (block_size - (concat_len % block_size)) % block_size;

	if (padding > 0) {
		uint8_t* new_S = (uint8_t*)realloc(S, concat_len + padding);
		if (!new_S) {
			free(S);
		}
		S = new_S;

		memset(S + concat_len, 0, padding);
		concat_len += padding;
	}
	//padded(S, S, concat_len*8, ctx->nb);

	printf("S = \n");
	print(concat_len * 8, S);

	//step 6
	uint8_t* temp = (uint8_t*)malloc((ctx->nk * 8) + (ctx->nb * 8));
	int tempLen = 0;

	//step 7
	int i = 0;

	//step 8
	uint8_t initialKey[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};

	uint8_t* K = (uint8_t*)malloc((ctx->nk * 8));

	memcpy(K, initialKey, ctx->nk * 8);

	printf("K = \n");
	print(ctx->nk * 8 * 8, K);

	KalynaKeyExpand((uint64_t*)K, ctx);

	uint8_t* IV = (uint8_t*)malloc((ctx->nb * 8));

	uint8_t* IV_S = (uint8_t*)malloc((concat_len + ctx->nb * 8));

	//step 9
	while (tempLen < ((ctx->nk * 64) + block_bitlen))
	{
		uint8_t I_to32[4];
		u32_to_bytes(I_to32, i);
		memcpy(IV, I_to32, 4);

		printf("IV = \n");
		print(ctx->nb * 8 * 8, IV);

		memset(IV + 4, 0, (ctx->nb * 8) - 4);

		printf("IV = \n");
		print(ctx->nb * 8 * 8, IV);

		memcpy(IV_S, IV, ctx->nb * 8);
		memcpy(IV_S + ctx->nb * 8, S, concat_len);

		BCC(ctx, IV_S, (concat_len + ctx->nb * 8) * 8, block_bitlen, temp + ((ctx->nb * 8) * i));
		tempLen += block_bitlen;

		printf("temp = \n");
		print(block_bitlen, temp + ((ctx->nb * 8) * i));

		i++;
	}

	printf("temp = \n");
	print(tempLen, temp);

	//step 10
	memcpy(K, temp, ctx->nk * 8);

	printf("K = \n");
	print(ctx->nk * 8 * 8, K);

	KalynaKeyExpand((uint64_t*)K, ctx);

	//step 11
	uint8_t* X = (uint8_t*)malloc((ctx->nb * 8));
	memcpy(X, temp + ctx->nk * 8, ctx->nb * 8);

	printf("X = \n");
	print(ctx->nb * 8 * 8, X);

	//step 12
	temp = NULL;
	uint8_t* new_temp = (uint8_t*)realloc(temp, no_of_bits_to_return / 8);
	tempLen = 0;

	//step 13
	i = 0;
	while (tempLen < no_of_bits_to_return)
	{
		KalynaEncipher((uint64_t*)X, ctx, (uint64_t*)X);
		memcpy(new_temp + (i * ctx->nb * 8), X, ctx->nb * 8);

		tempLen += block_bitlen;
		i++;
	}

	printf("new_temp = \n");
	print(no_of_bits_to_return, new_temp);

	//step 14-15
	memcpy(requested_bits, new_temp, no_of_bits_to_return / 8);

	printf("requested_bits = \n");
	print(no_of_bits_to_return, requested_bits);


	//step 9.2
	//uint8_t dest2[16];
	//BCC(ctx, S, concat_len*8, block_bitlen, dest2);
	//printf("after BCC = \n");
	//print(block_size*8, dest2);

	free(S);
	free(temp);
	free(IV);
	free(IV_S);
	free(X);
	free(new_temp);

	return 0;
}

void CTRMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	uint8_t* IV,
	uint8_t* M,
	size_t M_bitlen,
	const char* inFile,
	const char* outFile
)
{
	int offset;
	std::vector<uint8_t> fileData;
	kalyna_t* ctx = KalynaInit(nb * 64, nk * 64);

	KalynaKeyExpand((uint64_t*)key, ctx);

	uint8_t gamma[64];

	createGamma(IV, ctx, gamma);

	printf("gamma (CTR mode) = \n");
	print(nb * 64, gamma);

	uint8_t feed[64];
	memcpy(feed, gamma, nb * 8);

	printf("ctr (CTR mode) = \n");
	print(nb * 64, feed);

	if (M == NULL) {
		if (inFile) {
			fileData = ReadAllBytes((char*)inFile);
			offset = ctrEncrypt(fileData.data(), fileData.size() * 8, gamma, feed, nb * 64, ctx, dest);
		}
		if (outFile) {
			std::vector<uint8_t> resultingData = std::vector<uint8_t>(dest, dest + fileData.size());

			WriteAllBytes(outFile, resultingData);
		}
	}
	else {
		offset = ctrEncrypt(M, M_bitlen, gamma, feed, nb * 64, ctx, dest);
	}
}

void CFBMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	uint8_t* IV,
	size_t q,
	uint8_t* M,
	size_t M_bitlen,
	const char* inFile,
	const char* outFile
)
{
	std::vector<uint8_t> fileData;
	kalyna_t* ctx = KalynaInit(nb * 64, nk * 64);

	KalynaKeyExpand((uint64_t*)key, ctx);

	uint8_t gamma[64];

	createGamma(IV, ctx, gamma);

	printf("gamma (CFB mode) = \n");
	print(nb * 64, gamma);

	if (M == NULL) {
		if (inFile) {
			fileData = ReadAllBytes((char*)inFile);
			cfbEncrypt(fileData.data(), fileData.size() * 8, q, gamma, ctx, dest);
		}
		if (outFile) {
			std::vector<uint8_t> resultingData = std::vector<uint8_t>(dest, dest + fileData.size());

			WriteAllBytes(outFile, resultingData);
		}
	}
	else {
		cfbEncrypt(M, M_bitlen, q, gamma, ctx, dest);
	}

}

void CMACMode(
	size_t nb,
	size_t nk,
	uint8_t* key,
	size_t q,
	uint8_t* M,
	size_t M_bitlen
)
{
	kalyna_t* ctx = KalynaInit(nb * 64, nk * 64);

	KalynaKeyExpand((uint64_t*)key, ctx);

	uint8_t feed[64];


	int res = CMAC(M, M_bitlen, q, ctx, dest);
	printf("CMAC (CMAC mode) = \n");
	print(nb * 64, dest);
}

void BlockCipherDFMode(
	size_t nb,
	size_t nk,
	uint8_t* M,
	size_t M_bitlen
)
{
	uint8_t feed[64];
	block_cipher_df(M, M_bitlen, nb * 64, nk * 64, feed);

	printf("%zu\n", nb);
	printf("%zu\n", nk);
	printf("feed = \n");
	print(nk * 64, feed);
}

uint8_t getBit(
	const uint8_t* src,
	size_t bit
)
{
	size_t byte = bit / 8;
	uint8_t current_bit = (uint8_t)(7 - bit % 8);

	return (src[byte] >> current_bit) & 1;
}

void setBit(
	uint8_t* dest,
	size_t bit,
	uint8_t value
)
{
	size_t byte = bit / 8;
	uint8_t current_bit = 7 - bit % 8;
	uint8_t temp = (uint8_t)(1 << current_bit);
	dest[byte] = (dest[byte] & (~temp)) | (value << current_bit);
}

void incGamma(
	uint8_t* gamma,
	size_t len
)
{
	for (size_t i = 0; i < len; i++)
	{
		gamma[i] += 1;
		if (gamma[i])
			break;
	}
}

void movBits(
	uint8_t* dest,
	size_t dest_bit,
	const uint8_t* src,
	size_t src_bit,
	size_t src_bits
)
{

	size_t i;
	for (i = 0; i < src_bits; i++)
	{
		uint8_t bit = getBit(src, src_bit + i);
		setBit(dest, dest_bit + i, bit);
	}
}

size_t padded(
	uint8_t* dest,
	const uint8_t* src,
	size_t src_len_bits,
	size_t nb
)
{
	size_t nb_bits = nb * 64;
	size_t add_bits = (nb_bits - src_len_bits % nb_bits) % nb_bits;
	size_t end_bit = src_len_bits + add_bits;
	size_t src_bytes = (src_len_bits + 7) / 8;
	size_t i;
	memcpy(dest, src, src_bytes);
	if (add_bits)
	{
		setBit(dest, src_len_bits, 1);

		for (i = 1; i < add_bits; i++)
			setBit(dest, src_len_bits + i, 0);
	}
	return end_bit;
}

size_t paddedBytes(
	uint8_t* dest,
	const uint8_t* src,
	size_t src_len_bits,
	size_t nb
)
{
	size_t nb_bits = nb * 64;
	size_t add_bits = (nb_bits - src_len_bits % nb_bits) % nb_bits;
	size_t end_bit = src_len_bits + add_bits;
	size_t src_bytes = (src_len_bits + 7) / 8;
	size_t i;
	memcpy(dest, src, src_bytes);
	if (add_bits)
	{
		setBit(dest, src_len_bits, 1);

		for (i = 1; i < add_bits; i++)
			setBit(dest, src_len_bits + i, 0);
	}
	return end_bit;
}

std::vector<uint8_t> ReadAllBytes(
	char* filePath
)
{
	// Відкриття файлу в двійковому режимі
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);

	if (!file) {
		std::cerr << "Не вдалося відкрити файл: " << filePath << std::endl;
		return {};
	}

	// Отримання розміру файлу
	std::streamsize fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// Створення вектора з відповідним розміром
	std::vector<uint8_t> buffer(fileSize);

	// Зчитування файлу у вектор
	if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
		std::cerr << "Не вдалося прочитати файл: " << filePath << std::endl;
		return {};
	}

	// Закриття файлу та повернення буфера
	file.close();
	return buffer;
}

void WriteAllBytes(
	const std::string& filePath,
	const std::vector<uint8_t>& data
)
{
	// Відкриття файлу в режимі двійкового виводу
	std::ofstream file(filePath, std::ios::binary);
	if (!file.is_open()) {
		throw std::runtime_error("Не вдалося відкрити файл для запису: " + filePath);
	}

	// Запис усіх байтів до файлу
	file.write(reinterpret_cast<const char*>(data.data()), data.size());
	if (!file) {
		throw std::runtime_error("Помилка запису даних у файл: " + filePath);
	}
}
