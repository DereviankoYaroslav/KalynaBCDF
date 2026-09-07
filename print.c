#include <stddef.h>
#include <stdint.h>

void print(int data_len, uint8_t data[])
{
	int i = 0;
	int data_size = data_len / 8;
	for (i = 0; i < data_size; i++)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X ", (unsigned int)data[i]);
		if (!((i + 1) % 16)) printf("\n");
	};
	if (data_len % 8 != 0)
	{
		if (!(i % 16)) printf("    ");
		printf("0x%02X ", (unsigned int)((data[i]) & (~((1 << (8 - (data_len % 8))) - 1))));
		if (!((i + 1) % 16)) printf("\n");
	};
	printf("\n");
};