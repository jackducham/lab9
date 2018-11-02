/************************************************************************
Lab 9 Nios Software

John Ducham, Fall 2018
Dong Kai Wang, Fall 2017
Christine Chen, Fall 2013

For use with ECE 385 Experiment 9
University of Illinois ECE Department
************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "aes.h"

/* Pointer to base address of AES module, make sure it matches Qsys */
volatile unsigned int * AES_PTR = (unsigned int *) 0x00000100;

/* Execution mode: 0 for testing, 1 for benchmarking */
int run_mode = 0;

/* char_to_hex
 * Convert a single character to the 4-bit value it represents.
 * Input:
 *  a character c (e.g. 'A')
 * Output:
 *  converted 4-bit value (e.g. 0xA)
 */
char char_to_hex(char c)
{
     char hex = c;

     if (hex >= '0' && hex <= '9')
	  hex -= '0';
     else if (hex >= 'A' && hex <= 'F') {
	  hex -= 'A';
	  hex += 10;
     }
     else if (hex >= 'a' && hex <= 'f') {
	  hex -= 'a';
	  hex += 10;
     }
     return hex;
}

/* chars_to_hex
 * Convert two characters to byte value it represents.
 * Inputs must be 0-9, A-F, or a-f.
 * Input:
 *  two characters c1 and c2 (e.g. 'A' and '7')
 * Output:
 *  converted byte value (e.g. 0xA7)
 */
char chars_to_hex(char c1, char c2)
{
     char hex1 = char_to_hex(c1);
     char hex2 = char_to_hex(c2);
     return (hex1 << 4) + hex2;
}

void xtime(unsigned char *x){
     unsigned char a = *x;
     *x = *x << 1;
     if((a & 0x80) >> 7){
	  *x = *x ^ 0x1b;
     }
}

/* mix_columns
 * Updates the input state by multiplying each word by a polynomial matrix.
 * Input:
 *  state - Pointer to 16x 8-bit array
 * Output:
 *  state - Pointer to 16x 8-bit array
 */
void mix_columns(unsigned char *state)
{
     for(int i = 0; i < 4; i++){
	  unsigned char a0 = *(state + 4*i + 0);
	  unsigned char a1 = *(state + 4*i + 1);
	  unsigned char a2 = *(state + 4*i + 2);
	  unsigned char a3 = *(state + 4*i + 3);
	  unsigned char xa0 = *(state + 4*i + 0);
	  unsigned char xa1 = *(state + 4*i + 1);
	  unsigned char xa2 = *(state + 4*i + 2);
	  unsigned char xa3 = *(state + 4*i + 3);
	  xtime(&xa0);
	  xtime(&xa1);
	  xtime(&xa2);
	  xtime(&xa3);
	  *(state + 4*i + 0) = xa0 ^ xa1 ^ a1 ^ a2 ^ a3;
	  *(state + 4*i + 1) = xa1 ^ xa2 ^ a2 ^ a3 ^ a0;
	  *(state + 4*i + 2) = xa2 ^ xa3 ^ a3 ^ a0 ^ a1;
	  *(state + 4*i + 3) = xa3 ^ xa0 ^ a0 ^ a1 ^ a2;
     }
}

/* shift_rows
 * Updates the input state by shifting each row.
 * Input:
 *  in - Pointer to 16x 8-bit array
 * Output:
 *  in - Pointer to 16x 8-bit array
 */
void shift_rows(unsigned char *in)
{
     for(int i = 1; i < 4; i++){
	  unsigned char x0 = *(in + (0 * 4) + i);
	  unsigned char x1 = *(in + (1 * 4) + i);
	  unsigned char x2 = *(in + (2 * 4) + i);
	  unsigned char x3 = *(in + (3 * 4) + i);
	  if(i == 1){
	       *(in + (0 * 4) + i) = x1;
	       *(in + (1 * 4) + i) = x2;
	       *(in + (2 * 4) + i) = x3;
	       *(in + (3 * 4) + i) = x0;
	  }
	  else if(i == 2){
	       *(in + (0 * 4) + i) = x2;
	       *(in + (1 * 4) + i) = x3;
	       *(in + (2 * 4) + i) = x0;
	       *(in + (3 * 4) + i) = x1;
	  }
	  else if(i == 3){
	       *(in + (0 * 4) + i) = x3;
	       *(in + (1 * 4) + i) = x0;
	       *(in + (2 * 4) + i) = x1;
	       *(in + (3 * 4) + i) = x2;
	  }
     }
}

/* add_round_key
 * Applies a round key to each word in the input state.
 * Input:
 *  state - Pointer to 16x 8-bit array
 *  round_key - Pointer to 4x 32-bit array
 * Output:
 *  state - Pointer to updated 16x 8-bit array
 */
void add_round_key(unsigned char *state, unsigned int *round_key)
{
     int i, j;
     for (i = 0; i < 4; ++i) {
	  for (j = 0; j < 4; ++j) {
	        unsigned char x = state[i*4 + j];
	        unsigned char y = (unsigned char) (((round_key[i] >> (8*(3-j))) & 0xff));
	       state[i*4 + j] = x ^ y;
	  }
     }
}

/* sub_word
 * Replaces each byte in the input with values from the S-box table.
 * Input:
 *  word - Pointer to 4x 8-bit array
 * Output:
 *  word - Pointer to 4x 8-bit array with substituted values
 */
void sub_word(unsigned char *word)
{
     int i;
     for (i = 0; i < 4; ++i) {
	  word[i] = aes_sbox[(int) word[i]];
     }
}

/* sub_bytes
 * Updates each byte in the input state with values from the S-box table.
 * Input:
 *  state - Pointer to 16x 8-bit array
 * Output:
 *  state - Pointer to 16x 8-bit array with updated values
 */
void sub_bytes(unsigned char *state)
{
     int i;
     for (i = 0; i < 4; ++i) {
	  sub_word(state + i*4);
     }
}

/* rotate_word
 * Rotates the input word by 1 byte.
 * Input:
 *  word - Pointer to 32-bit integer
 * Output:
 *  word - Pointer to rotated 32-bit integer
 */
void rotate_word(unsigned int *word)
{
     unsigned int temp = *word >> 24 & 0xff;
     *word = *word << 8;
     *word = *word | temp;
}

/* chars_to_word
 * Concatenates 4 input chars and stores the result as an integer.
 * Input:
 *  in - Pointer to 4x 8-bit char array
 *  out - Pointer to 32-bit integer
 * Output:
 *  out - Pointer to new integer
 */
void chars_to_word(unsigned char *in, unsigned int *out)
{
     int i;
     unsigned int temp;
     *out = 0;
     for (i = 0; i < 4; ++i) {
	  temp = (unsigned int) in[i] << (8 * (3-i));
	  *out = *out | temp;
     }
}

/* chars_to_state
 * Stores 16 8-bit chars as 4 32-bit integers
 * Input:
 *  in - Pointer to 16x 8-bit array
 *  out - Pointer to 4x 32-bit array
 * Output:
 *  out - Pointer to new array of integers
 */
void chars_to_state(unsigned char *in, unsigned int *out)
{
     int i;
     for (i = 0; i < 4; ++i) {
	  chars_to_word(in + i*4, out + i);
     }
}

/* key_expansion
 * Generates a series of round keys and stores them in a key schedule.
 * Input:
 *  key - Pointer to 16x 8-bit array containing the cipher key (4x4 matrix)
 * Output:
 *  key_schedule - Pointer to 44x 32-bit array containing the key schedule
 */
void key_expansion(unsigned char *key, unsigned int *key_schedule)
{
     unsigned int word = 0;
     int i = 0;

     /* copy cipher key into first round key */
     chars_to_state(key, key_schedule);

     /* perform key expansion */
     for (i = 4; i < 44; ++i) {
	  word = key_schedule[i - 1];
	  unsigned int x = key_schedule[i-4];
	  if (i % 4 == 0) {
	       rotate_word(&word);
	       sub_word((unsigned char *) &word);
	       word = word ^ Rcon[i/4];
	  }
	  key_schedule[i] = x ^ word;
     }
}

/* aes
 * AES encryption
 * Input:
 *  msg - Pointer to 16x 8-bit array containing the input message
 *  key_schedule - Pointer to 44x 32-bit array containing the key schedule
 *                 Round keys are stored in consecutive groups of four
 * Output:
 *  msg_out - Pointer to 16x 8-bit array containing the encrypted message
 */
void aes(unsigned char *msg, unsigned int *key_schedule, unsigned char *msg_out)
{
     int i;
     unsigned char state[16];

     /* intermediate results are kept in state to avoid mangling input */
     for (i = 0; i < 16; ++i) {
	  state[i] = msg[i];
     }

     /* perform encryption */
     add_round_key(state, key_schedule);

     for (i = 1; i < 10; ++i) {
	  sub_bytes(state);
	  shift_rows(state);
	  mix_columns(state);
	  add_round_key(state, key_schedule + i*4);
     }
     sub_bytes(state);
     shift_rows(state);
     add_round_key(state, key_schedule + 40);

     /* copy results to output */
     for (i = 0; i < 16; ++i) {
	  msg_out[i] = state[i];
     }

}

/* encrypt
 * Perform AES encryption in software.
 * Input:
 *  msg_ascii - Pointer to 32x 8-bit array containing the input message in ASCII
 *  key_ascii - Pointer to 32x 8-bit array containing the input key in ASCII
 * Output:
 *  msg_enc - Pointer to 4x 32-bit array that contains the encrypted message
 *  key - Pointer to 4x 32-bit array that contains the input key
 */
void encrypt(unsigned char *msg_ascii, unsigned char *key_ascii,
	     unsigned int *msg_enc, unsigned int *key)
{
     int i, j, k;
     unsigned char byte;
     unsigned char cipher_key[16];
     unsigned char msg[16];
     unsigned char msg_out[16];
     unsigned int key_schedule[44];
     unsigned int word;

     /* get key & msg by converting key_ascii and msg_ascii */
     k = 0;
     for (i = 0; i < 4; ++i) {
	  key[i] = 0;
	  for (j = 0; j < 7; j = j + 2) {
	       byte = chars_to_hex(key_ascii[i*8 + j], key_ascii[i*8 + j+1]);
	       cipher_key[k] = byte;
	       word = (unsigned int) byte << 8 * (3 - j/2);
	       key[i] = key[i] | word;
	       byte = chars_to_hex(msg_ascii[i*8 + j], msg_ascii[i*8 + j+1]);
	       msg[k++] = byte;
	  }
     }

     /* generate key schedule */
     key_expansion(cipher_key, key_schedule);

     /* generate encrypted message */
     aes(msg, key_schedule, msg_out);

     /* convert encrypted message to 4x 32-bit array */
     chars_to_state(msg_out, msg_enc);
}

/* decrypt
 * Perform AES decryption in hardware.
 * Input:
 *  msg_enc - Pointer to 4x 32-bit array containing the encrypted message
 *  key - Pointer to 4x 32-bit array that contains the input key
 * Output:
 *  msg_dec - Pointer to 4x 32-bit array containing the decrypted message
 */
void decrypt(unsigned int *msg_enc, unsigned int *msg_dec, unsigned int *key)
{
     /* TODO */
}

/* main
 * Allows the user to enter the message, key, and select execution mode
 */
int main()
{
     /* Input Message and Key as 32x 8-bit ASCII Characters ([33] is for NULL
      * terminator)
      */
     unsigned char msg_ascii[33];
     unsigned char key_ascii[33];
     /* Key, Encrypted Message, and Decrypted Message in 4x 32-bit Format to
      * facilitate Read/Write to Hardware
      */

     unsigned int key[4];
     unsigned int msg_enc[4];
     unsigned int msg_dec[4];

     printf("Select execution mode: 0 for testing, 1 for benchmarking: ");
     scanf("%d", &run_mode);

     if (run_mode == 0) {
	  /* Continuously Perform Encryption and Decryption */
	  while (1) {
	       int i = 0;
	       msg_ascii[0] = 'e';
	       msg_ascii[1] = 'c';
	       msg_ascii[2] = 'e';
	       msg_ascii[3] = '2';
	       msg_ascii[4] = '9';
	       msg_ascii[5] = '8';
	       msg_ascii[6] = 'd';
	       msg_ascii[7] = 'c';
	       msg_ascii[8] = 'e';
	       msg_ascii[9] = 'c';
	       msg_ascii[10] = 'e';
	       msg_ascii[11] = '2';
	       msg_ascii[12] = '9';
	       msg_ascii[13] = '8';
	       msg_ascii[14] = 'd';
	       msg_ascii[15] = 'c';
	       msg_ascii[16] = 'e';
	       msg_ascii[17] = 'c';
	       msg_ascii[18] = 'e';
	       msg_ascii[19] = '2';
	       msg_ascii[20] = '9';
	       msg_ascii[21] = '8';
	       msg_ascii[22] = 'd';
	       msg_ascii[23] = 'c';
	       msg_ascii[24] = 'e';
	       msg_ascii[25] = 'c';
	       msg_ascii[26] = 'e';
	       msg_ascii[27] = '2';
	       msg_ascii[28] = '9';
	       msg_ascii[29] = '8';
	       msg_ascii[30] = 'd';
	       msg_ascii[31] = 'c';
	       msg_ascii[32] = '\0';
	       //printf("\nEnter Message:\n");
	       key_ascii[0] = '0';
	       key_ascii[1] = '0';
	       key_ascii[2] = '0';
	       key_ascii[3] = '1';
	       key_ascii[4] = '0';
	       key_ascii[5] = '2';
	       key_ascii[6] = '0';
	       key_ascii[7] = '3';
	       key_ascii[8] = '0';
	       key_ascii[9] = '4';
	       key_ascii[10] = '0';
	       key_ascii[11] = '5';
	       key_ascii[12] = '0';
	       key_ascii[13] = '6';
	       key_ascii[14] = '0';
	       key_ascii[15] = '7';
	       key_ascii[16] = '0';
	       key_ascii[17] = '8';
	       key_ascii[18] = '0';
	       key_ascii[19] = '9';
	       key_ascii[20] = '0';
	       key_ascii[21] = 'a';
	       key_ascii[22] = '0';
	       key_ascii[23] = 'b';
	       key_ascii[24] = '0';
	       key_ascii[25] = 'c';
	       key_ascii[26] = '0';
	       key_ascii[27] = 'd';
	       key_ascii[28] = '0';
	       key_ascii[29] = 'e';
	       key_ascii[30] = '0';
	       key_ascii[31] = 'f';
	       key_ascii[32] = '\0';
	       //scanf("%s", msg_ascii);
	       //printf("\n");
	       //printf("\nEnter Key:\n");
	       //scanf("%s", key_ascii);
	       //printf("\n");
	       printf("\nmsg_ascii:\n");
	       printf("%s", msg_ascii);
	       printf("\nkey_ascii:\n");
	       printf("%s", key_ascii);
	       encrypt(msg_ascii, key_ascii, msg_enc, key);
	       printf("\nkey:\n");
	       for (i = 0; i < 4; i++) {
		    printf("%08x", key[i]);
	       }
	       printf("\nEncrpted message is: \n");
	       for (i = 0; i < 4; i++) {
		    printf("%08x", msg_enc[i]);
	       }
	       printf("\n");
	       decrypt(msg_enc, msg_dec, key);
	       printf("\nDecrypted message is: \n");
	       for (i = 0; i < 4; i++) {
		    printf("%08x", msg_dec[i]);
	       }
	       printf("\n");
	  }
     }
     else {
	  /* Run the Benchmark */
	  int i = 0;
	  int size_KB = 2;
	  /* Choose a random Plaintext and Key */
	  for (i = 0; i < 32; i++) {
	       msg_ascii[i] = 'a';
	       key_ascii[i] = 'b';
	  }
	  /* Run Encryption */
	  clock_t begin = clock();
	  for (i = 0; i < size_KB * 64; i++)
	       encrypt(msg_ascii, key_ascii, msg_enc, key);
	  clock_t end = clock();
	  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	  double speed = size_KB / time_spent;
	  printf("Software Encryption Speed: %f KB/s \n", speed);
	  /* Run Decryption */
	  begin = clock();
	  for (i = 0; i < size_KB * 64; i++)
	       decrypt(msg_enc, msg_dec, key);
	  end = clock();
	  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	  speed = size_KB / time_spent;
	  printf("Hardware Encryption Speed: %f KB/s \n", speed);
     }
     return 0;
}
