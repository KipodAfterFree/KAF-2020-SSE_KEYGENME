#include <stdio.h>
#include <inttypes.h>
#include <immintrin.h>

const static uint8_t p_box[16] = {2, 7, 5, 14, 1, 12, 6, 3,
				  16, 8, 11, 15, 13, 10, 9, 4};

const static uint8_t x_box[16] = {2, 3, 5, 7, 11, 13, 17, 19,
				  23, 29, 31, 37, 41, 43, 47};

const static uint8_t flag[32] = {0x43, 0x51, 0x43, 0x36, 0x40, 0x52, 0x21, 0x55,
				 0x24, 0x42, 0x5b, 0x68, 0x7d, 0x67, 0x1f, 0x7b,
				 0x5d, 0x7e, 0x4e, 0x0e, 0x58, 0x04, 0x22, 0x40,
				 0x1e, 0x14, 0x16, 0x2c, 0x20, 0x22, 0x26, 0x34 };

size_t get_input(uint8_t* buf, size_t size) {
	size_t i = 0;
	while (i < size) {
		uint8_t ch = getchar();
		if (ch == '\n' || ch == '\0') {
			break;
		}
		buf[i] = ch;
		i++;
	}
	return i;
}

// PKCS5 Padding
void pad(uint8_t* buf, size_t size, size_t padded_sz) {
	if (size > padded_sz) {
		printf("More bytes read than expected, exiting...\n");
		exit(1);
	}
	if (size == padded_sz) {
		return;
	}
	uint8_t pad = padded_sz - size;
	for (size_t j = size; j < padded_sz; j++) {
		buf[j] = pad;
	}
}

int check_login(const uint8_t* pw, size_t sz) {
	if (sz % 16) {
		printf("Input size not multiple of block length, exiting...\n");
		exit(1);
	}

	uint8_t* cipher = (uint8_t*)malloc(sz * sizeof(uint8_t));
	for (size_t i = 0; i < sz; i += 16) {
		__m128i ones = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1,
					    1, 1, 1, 1, 1, 1, 1, 1); 	
		__m128i mask = _mm_lddqu_si128((__m128i*)(p_box));
		__m128i xorer = _mm_lddqu_si128((__m128i*)(x_box));

		mask = _mm_sub_epi8(mask, ones);
		__m128i loaded = _mm_lddqu_si128((__m128i*)(pw + i));
		__m128i shuffled = _mm_shuffle_epi8(loaded, mask);
		shuffled = _mm_xor_si128(shuffled, xorer);	
		_mm_storeu_si128((__m128i*)(cipher + i), shuffled);
	}
	
	for (size_t i = 0; i < sz; i++) {
		if (cipher[i] != flag[i]) {
			free(cipher);
			return 0;
		}
	}
	free(cipher);
	return 1;
}

int main(int argc, char** argv) {
	printf("###############################\n");
	printf("### WELCOME TO SSE_KEYGENME ###\n");
	printf("###      ENJOY YOUR STAY    ###\n");
	printf("###############################\n");
	
	uint8_t pw[32];
	printf("Enter key:\n> ");
	size_t bytes_read = get_input(pw, 32);
	if (bytes_read < 1) {
		printf("Please enter a key.\n");
		exit(1);
	}
	pad(pw, bytes_read, 32);
	int status = check_login(pw, 32);
	if (status) {
		printf("Success! Enjoy the rest of the competition :)\n");
	} else {
		printf("Wrong key, try again...\n");
	}
}
