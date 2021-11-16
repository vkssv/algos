#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define SIZE (16)

void print_array(uint32_t *array) {

	uint32_t *elem = array;
	int i = SIZE;

	printf("Color codes: 16-bit\n");
	while(i-- > 0){
		printf("==> 0x%08x, %d\n", *elem, *elem);
		elem++;
	}
}


int main(int argc, char *argv[]) {

	uint32_t hex_color_codes[SIZE] = { 0x00000000, 
							0x00FFFFFF,
							0x00FF0000,
							0x0000FF00,
							0x000000FF,
							0x00FFFF00,
							0x0000FFFF,
							0x00FF00FF,
							0x00C0C0C0,
							0x00808080,
							0x00800000,
							0x00808000,
							0x00008000,
							0x00800080,
							0x00008080,
							0x00000080
	};

	uint32_t *start = hex_color_codes;
	uint32_t *elem;
	uint32_t temp;
	uint8_t swapped = 1;
	int i = SIZE;

	(void) argc; // cast to nothing to avoid warnings
	(void) argv;


	print_array(hex_color_codes);

	// time: O(n^2) loop inside loop, space: O(1) reuses the same array and temp/swapped
	// slow for any type (half-sorted/random data/reversed) but space efficient

	while (swapped) { 
		swapped = 0;
		for (i=0; i<SIZE-1; i++) { 
			if (hex_color_codes[i] > hex_color_codes[i+1]) { 
					temp = hex_color_codes[i];
					hex_color_codes[i] = hex_color_codes[i+1];
					hex_color_codes[i+1] = temp;
					swapped = 1;
			}
		}
	}

/*
	while(swapped) {
		swapped = 0;
		elem = start;
		i = 0;
		while(!((i+1) == SIZE)){
			i++;
			if (*elem > *(elem+1)) {
				temp = *elem;
				*elem = *(elem+1);
				*(elem+1) = temp;
				swapped = 1;
			}
			elem++;
		} 
	}
*/
	
	print_array(hex_color_codes);

	return EXIT_SUCCESS;
}

	


	
