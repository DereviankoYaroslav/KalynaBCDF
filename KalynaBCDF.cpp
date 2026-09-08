#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <bitset>

#ifndef __linux__
	#include <windows.h>
#endif

#include <iomanip>
#include <fstream>
#include <sstream>
#include <cmath> 

#include "params.h"

//Kalyna
#include "kalyna.h"
#include "transformations.h"
#ifndef __linux__
	#include "tables.c"
#endif

using namespace std;
#pragma warning(disable:4996)
#pragma comment(lib, "bcrypt.lib")

//uint8_t buf[64];
//uint8_t dest[16000000];
uint8_t pool[ENT_POOL_SIZE];
uint8_t chunk[CHUNK_SIZE];

unsigned char repetitionCountTestA = 0;
int repetitionCountTestB = 1;
int repetitionCountTestC = 11;

unsigned char adaptiveProportionTestA = 0;
int adaptiveProportionTestB = 1;
int adaptiveProportionTestW = W;
int adaptiveProportionTestC = 177;
int adaptiveProportionTestI = 1;

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

void BlockCipherDFMode(
	kalyna_t* ctx,
	size_t nb,
	size_t nk,
	uint8_t* M,
	size_t M_bitlen
);

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
		printf("0x%02X, ", (unsigned int)data[i]);
		if (!((i + 1) % 16)) printf("\n");
	};
	if (data_len % BITS_IN_BYTE != 0)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X, ", (unsigned int)((data[i]) & (~((1 << (BITS_IN_BYTE - (data_len % BITS_IN_BYTE))) - 1))));
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
	alignas(8) uint8_t chaining_value[64] = { 0 };
	alignas(8) uint8_t input_block[64] = { 0 };
	memset(chaining_value, 0, outlen / 8);

	size_t outbytes = outlen / 8;
	size_t n = data_bitlen / outlen;
	//printf("n = %d", n);

	//printf("ch val = \n");
	//print(outlen, chaining_value);

	//printf("data = \n");
	//print(data_bitlen, (uint8_t*)data);

	for (size_t i = 0; i < n; i++)
	{
		for (size_t j = 0; j < outbytes; j++) {
			//std::cout << "i =  " << i << "outlen / 8 = " << outlen / 8 << endl;
			input_block[j] = chaining_value[j] ^ data[j];
			//std::cout << "input block val is " << endl;
			//printf("0x%02x\n", input_block[j]);
			//std::cout << "chaining_value val is " << endl;
			//printf("0x%02x\n", chaining_value[j]);
			//std::cout << "data val is " << endl;
			//printf("0x%02x\n", data[j]);
		}
		data += outbytes;
		//printf("input_block = \n");
		//print(outlen, input_block);
		KalynaEncipher((uint64_t*)input_block, ctx, (uint64_t*)chaining_value);
	}

	memcpy(dest, chaining_value, outbytes);
	//printf("chaining_value = \n");
	//print(outlen, chaining_value);
}

int block_cipher_df(
	kalyna_t* ctx,
	const uint8_t* input_string,
	size_t input_len,
	uint32_t no_of_bits_to_return,
	uint8_t* requested_bits
)
{
	// step 1
	if (no_of_bits_to_return > KEY_BITLEN) {
		return 1;
	}

	// step 2
	uint8_t L[4];
	u32_to_bytes(L, input_len / 8);

	// step 3
	uint8_t N[4];
	u32_to_bytes(N, no_of_bits_to_return / 8);

	// step 4
	size_t concat_len = 4 + 4 + (input_len / 8) + 1;
	//uint8_t* S = (uint8_t*)malloc(concat_len);
	alignas(8) uint8_t S[ENT_POOL_SIZE + 128];

	uint8_t val[1] = { 0x80 };

	memcpy(S, L, 4);
	memcpy(S + 4, N, 4);
	memcpy(S + 8, input_string, (input_len / 8));
	memcpy(S + 8 + (input_len / 8), val, 1);

	//printf("S = \n");
	//print(concat_len * 8, S);

	//step 5
	size_t padding = (BLOCK_LEN - (concat_len % BLOCK_LEN)) % BLOCK_LEN;

	if (padding > 0) {
		/*uint8_t* new_S = (uint8_t*)realloc(S, concat_len + padding);
		if (!new_S) {
			free(S);
			return 1;
		}
		S = new_S;*/

		memset(S + concat_len, 0, padding);
		concat_len += padding;
	}
	//padded(S, S, concat_len*8, ctx->nb);

	//printf("S = \n");
	//print(concat_len * 8, S);

	//step 6
	alignas(8) uint8_t temp[KEY_LEN + BLOCK_LEN];
	//uint8_t* temp = (uint8_t*)malloc((ctx->nk * 8) + (ctx->nb * 8));
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

	alignas(8) uint8_t K[KEY_LEN];
	//uint8_t* K = (uint8_t*)malloc((ctx->nk * 8));

	memcpy(K, initialKey, ctx->nk * 8);

	//printf("K = \n");
	//print(ctx->nk * 8 * 8, K);

	KalynaKeyExpand((uint64_t*)K, ctx);

	alignas(8) uint8_t IV[BLOCK_LEN];
	//uint8_t* IV = (uint8_t*)malloc((ctx->nb * 8));

	//uint8_t* IV_S = (uint8_t*)malloc((concat_len + ctx->nb * 8));
	alignas(8) uint8_t IV_S[ENT_POOL_SIZE + 128];

	//step 9
	while (tempLen < (KEY_LEN + BLOCK_LEN))
	{
		uint8_t I_to32[4];
		u32_to_bytes(I_to32, i);
		memcpy(IV, I_to32, 4);

		//printf("IV = \n");
		//print(ctx->nb * 8 * 8, IV);

		memset(IV + 4, 0, (ctx->nb * 8) - 4);

		//printf("IV = \n");
		//print(ctx->nb * 8 * 8, IV);

		memcpy(IV_S, IV, ctx->nb * 8);
		memcpy(IV_S + ctx->nb * 8, S, concat_len);

		BCC(ctx, IV_S, (concat_len + ctx->nb * 8) * 8, BLOCK_BITLEN, temp + ((ctx->nb * 8) * i));
		tempLen += BLOCK_LEN;

		//printf("temp = \n");
		//print(BLOCK_LEN * 8, temp + ((ctx->nb * 8) * i));

		i++;
	}

	//printf("temp = \n");
	//print(tempLen * 8, temp);

	//step 10
	memcpy(K, temp, ctx->nk * 8);

	//printf("K = \n");
	//print(ctx->nk * 8 * 8, K);

	KalynaKeyExpand((uint64_t*)K, ctx);

	//step 11
	alignas(8) uint8_t X[BLOCK_LEN];
	//uint8_t* X = (uint8_t*)malloc((ctx->nb * 8));
	memcpy(X, temp + ctx->nk * 8, ctx->nb * 8);

	//printf("X = \n");
	//print(ctx->nb * 8 * 8, X);

	//step 12
	uint8_t new_temp[KEY_LEN];
	//temp = NULL;
	//uint8_t* new_temp = (uint8_t*)realloc(temp, no_of_bits_to_return / 8);
	int tempBitlen = 0;

	//step 13
	i = 0;
	while (tempBitlen < no_of_bits_to_return)
	{
		KalynaEncipher((uint64_t*)X, ctx, (uint64_t*)X);
		memcpy(new_temp + (i * ctx->nb * 8), X, ctx->nb * 8);

		tempBitlen += BLOCK_BITLEN;
		i++;
	}

	//printf("new_temp = \n");
	//print(no_of_bits_to_return, new_temp);

	//step 14-15
	memcpy(requested_bits, new_temp, no_of_bits_to_return / 8);

	//printf("requested_bits = \n");
	//print(no_of_bits_to_return, requested_bits);

	//free(S);
	//free(IV_S);

	return 0;
}

void BlockCipherDFMode(
	kalyna_t* ctx,
	size_t nb,
	size_t nk,
	uint8_t* M,
	size_t M_bitlen
)
{
	uint8_t feed[64];
	block_cipher_df(ctx, M, M_bitlen, NO_OF_BITS_TO_RETURN, feed);

	printf("%zu\n", nb);
	printf("%zu\n", nk);
	printf("feed = \n");
	print(NO_OF_BITS_TO_RETURN, feed);
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

int repetitionCountTest(
	unsigned char sample
) 
{
	if (sample == repetitionCountTestA) {
		repetitionCountTestB++;
		if (repetitionCountTestB >= repetitionCountTestC) {
			return 1;
		}
	}
	else {
		repetitionCountTestA = sample;
		repetitionCountTestB = 1;
	}

	return 0;
}

int adaptiveProportionTest(
	unsigned char sample
)
{
	if (adaptiveProportionTestI < adaptiveProportionTestW) {

		adaptiveProportionTestI++;

		if (adaptiveProportionTestA == sample) {
			adaptiveProportionTestB++;
		}

		if (adaptiveProportionTestB >= adaptiveProportionTestC) {
			return 1;
		}
	}
	else {
		adaptiveProportionTestI = 1;
		adaptiveProportionTestB = 1;
		adaptiveProportionTestA = sample;
	}

	return 0;
}

int main()
{
	//SetConsoleCP(1251);
	//SetConsoleOutputCP(1251);
	size_t nb, nk;

	kalyna_t* ctx = KalynaInit(BLOCK_BITLEN, KEY_BITLEN);

	uint8_t M_Block_cipher_df[38] = { 0x02, 0xE4, 0xA4, 0xD8, 0xD6, 0x35, 0x10, 0x5C, 0x0F, 0x4F, 0x6F, 0xD0, 0x31, 0x5B, 0xDC, 0x90,
	0x78, 0x96, 0x83, 0x9C, 0x83, 0xCC, 0x9F, 0x44, 0xA7, 0x33, 0x09, 0xC9, 0x2F, 0x24, 0x1A, 0xB7,
	0x71, 0x91, 0x73, 0x9D, 0xA7, 0x90 };

	BlockCipherDFMode(ctx, NB, NK, M_Block_cipher_df, 38 * 8);

	int pool_counter = 0;
	int counter = 0;
	unsigned char ent_byte = 0;
	size_t total_extracted_bytes = 0;

	FILE* in = fopen("synthetic_raw_noise.dat", "rb");
	if (!in) {
		perror("Failed to open input file");
		return 1;
	}

	std::string resultFileName = "BiasedDataExtMODE" + std::to_string(KALYNA_EXTRACTOR_MODE) + ".dat";

	FILE* out = fopen(resultFileName.c_str(), "ab");
	if (!out) {
		perror("Failed to open output file");
		return 1;
	}

	if (fread(&ent_byte, 1, 1, in) != 1) return 1;

	printf("0x%02X\n", ent_byte);

	repetitionCountTestA = ent_byte;
	adaptiveProportionTestA = ent_byte;

	while (counter < 1024) {
		if (fread(&ent_byte, 1, 1, in) != 1) break;

		printf("0x%02X\n", ent_byte);

		if (repetitionCountTest(ent_byte) != 0) {
			goto errorRCT;
		}

		if (adaptiveProportionTest(ent_byte) != 0) {
			goto errorAPT;
		}

		counter++;
	}

	printf("End of start-up tests\n");

	counter = 0;
	size_t bytes_read;

	while (total_extracted_bytes < TARGET_EXTRACTED_BYTES &&
		(bytes_read = fread(chunk, 1, CHUNK_SIZE, in)) > 0) {

		for (int i = 0; i < bytes_read; i++) {
			unsigned char ent_byte = chunk[i];

			if (repetitionCountTest(ent_byte) != 0) {
				goto errorRCT;
			}

			if (adaptiveProportionTest(ent_byte) != 0) {
				goto errorAPT;
			}

			pool[pool_counter] = ent_byte;

			pool_counter++;

			if (pool_counter >= ENT_POOL_SIZE) {

				//printf("Pool = \n");
				//print(ENT_POOL_SIZE*8, pool);
				//printf("\n");
				uint8_t feed[KEY_LEN];
				block_cipher_df(ctx, pool, ENT_POOL_SIZE * 8, NO_OF_BITS_TO_RETURN, feed);
				//printf("Extractor output = \n");
				//print(NO_OF_BITS_TO_RETURN, feed);
				//printf("\n");

				if (fwrite(feed, 1, KEY_LEN, out) != KEY_LEN) {
					perror("Write error");
					goto cleanup;
					break;
				}

				total_extracted_bytes += KEY_LEN;

				pool_counter = 0;

				if (total_extracted_bytes >= TARGET_EXTRACTED_BYTES) {
					break;
				}
			}

			//counter++;
		}
	}

	printf("Successfully extracted %zu bytes of uniform noise.\n", total_extracted_bytes);

	fclose(in);
	fclose(out);
	KalynaDelete(ctx);

	return 0;

errorRCT:
	printf("RCT error\n");
	if (out) 
	{
		fclose(out);
	}
	KalynaDelete(ctx);
	return 1;

errorAPT:
	printf("APT error\n");
	if (out) 
	{
		fclose(out);
	}
	KalynaDelete(ctx);
	return 1;

cleanup:
	fclose(in);
	fclose(out);
	KalynaDelete(ctx);
}
