#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//Sebasatien Ghent EEE-4748-001 Extra Credit code submission
//SHA-1 Interpretation


// Define SHA-1 circular left shift macro
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c)))) // 
// Initial hash values defined in the SHA-1 specification
uint32_t h[5] = {
    0x67452301, // h0
    0xEFCDAB89, // h1
    0x98BADCFE, // h2
    0x10325476, // h3
    0xC3D2E1F0  // h4
};

// Temporary variables used in the main loop
uint32_t a, b, c, d, e;

// Function prototypes
uint8_t* appendOneBit(uint8_t *message, size_t *length);//Meant to append 1 bit
uint8_t* appendZeroBits(uint8_t *message, size_t *length); //Append 0 bits after 1 bit
uint8_t* appendMessageLength(uint8_t *message, size_t *length, size_t originalLength); //Append the Message length to message

uint8_t* appendOneBit(uint8_t *message, size_t *length) {//Adds one bit to end of message
    size_t newLength = *length + 1; //Add one bit 
    message = realloc(message, newLength); // Resize the message buffer to new length
    message[*length] = 0x80; // Append '0x80' to the message (80 bits)
    *length = newLength; // Update the length through length pointer
    return message;
}

uint8_t* appendZeroBits(uint8_t *message, size_t *length) { //Appends rest with 0s 
    size_t bitsNeeded = 448 - ((*length * 8) % 512); //0 bits needed, 
    size_t bytesNeeded = bitsNeeded / 8; 
    if (bitsNeeded % 8 != 0) { //Takes the remainding bits if it indivisible by 8 and appends one byte until the number of 0's needed is divisible by 8
        bytesNeeded++; // In case there's a remainder
    } 
    size_t newLength = *length + bytesNeeded;// New length after applying 0s needed
    message = realloc(message, newLength); // Resize to new length
    memset(message + *length, 0, bytesNeeded); // Append '0' bytes
    *length = newLength;// Update length through pointing address 
    return message; //Return 0 appended message
}

uint8_t* appendMessageLength(uint8_t *message, size_t *length, size_t originalLength) {// Appending The Message Length to the message
    size_t newLength = *length + 8; // Increase length to accommodate 8-bit length 
    message = realloc(message, newLength); //Resize memory block to new length 
    uint64_t bitLength = originalLength * 8; // Convert length to bits
    // Convert to big-endian and append
    for (int i = 0; i < 8; i++) {
        message[*length + i] = (bitLength >> (56 - i * 8)) & 0xFF; // Message Length bit shifted 56 bits 8 times each time appending 32 bits
    }
    *length = newLength; //Update length's value with newLength
    return message;
}
//For each Chunk break down into 32 bit big-endian words
void processChunk(uint8_t *chunk) {
    uint32_t w[80], a, b, c, d, e, f, k, temp;  //Initalize variables in unsigned integer 32-bit 
    
    
    int i;

    //Initialize the first 16 words in the array w[0..15] 
    //Break Chunk into 32-bit big endian words
    for (i = 0; i < 16; i++) {
        //Shift the first byte left by 24 bits to place it in the highest-order byte position.
        //Shift the second byte left by 16 bits to place it in the next highest-order byte position.
        //Shift the third byte left by 8 bits to place it in the second lowest-order byte position.
        //Keep the fourth byte as is, in the lowest-order byte position.
        //Bitwise OR '|' to combine these four bytes into a single 32-bit word.
        w[i] = (uint32_t)chunk[i*4] << 24 | (uint32_t)chunk[i*4+1] << 16 | (uint32_t)chunk[i*4+2] << 8 | (uint32_t)chunk[i*4+3];
}

    //Extend the sixteen 32-bit words into eighty 32-bit words
    for (i = 16; i < 80; i++) {
        w[i] = LEFTROTATE(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    //Initialize hash value for this chunk
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    //Main function loop
    //Format Followed through Wikipedia
    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        //Sha-1 instructions
        temp = LEFTROTATE(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = LEFTROTATE(b, 30);
        b = a;
        a = temp;
    }

    //Add this chunk's hash to result so far
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

void produceFinalHashValue(uint32_t *h, uint8_t *finalHash) {
    //Loop through each of the 5 final hash values (h0(a) to h4(b)) 
    for (int i = 0; i < 5; i++) {
        //Extract the most significant byte (MSB) of the current hash value by shifting it right 24 bits and isolating the last byte.
        
        finalHash[i*4] = (h[i] >> 24) & 0xFF;
        
        //Extract the second most significant byte of the current hash value by shifting it right 16 bits and isolating the byte.
        
        finalHash[i*4+1] = (h[i] >> 16) & 0xFF;
        
        //Extract the third most significant byte of the current hash value by shifting it right 8 bits and isolating the byte.
        
        finalHash[i*4+2] = (h[i] >> 8) & 0xFF;
        
        //Extract the least significant byte (LSB) of the current hash value directly isolating the last byte without shifting.
        
        finalHash[i*4+3] = h[i] & 0xFF;
    }
}


    

int main() {
    char* originalMessage = "Crypto";//Character pointer for original message
    printf(originalMessage);
    size_t originalLength = strlen(originalMessage);//Size of original message in bytes
    size_t length = originalLength; //Length's value in 32 byte size representation
    uint8_t *message; //Message pointer to be used to copy both original message and the length of the message in 8 bit representation (Base64) 

    //Allocate initial buffer and copy the original message
    message = malloc(length); //Sets message pointer to point to the memory address of the buffer of size length
    memcpy(message, originalMessage, length); // Copies the original message and its length into message in 8 bit representation
    
    //Perform the SHA-1 pre-processing steps (applying padding)
    //Append One Bit at end of message 
    message = appendOneBit(message, &length);
    //Followed by appending Zero bits afterwards
    message = appendZeroBits(message, &length);
    //Followed by appending the message length to message
    message = appendMessageLength(message, &length, originalLength);
    //End of padding


    //Process each 64-byte chunk where i is less than the resultant message after padding has been applied, Process every 64 chunks (Base64)
    for (size_t i = 0; i < length; i += 64) {
        //For each set of 64 bits
        processChunk(message + i);
    }
    //Where the final hash would go.
    uint8_t finalHash[20];
    //Produce the final hash
    produceFinalHashValue(h, finalHash);

    // Print the final hash in hexadecimal
    printf("\nFinal hash in hexadecimal:\n");
    for (int i = 0; i < 20; i++) {
        printf("%02x", finalHash[i]);
    }
    printf("\n");
    
    // Free the allocated message buffer
    free(message);
    return 0;
}
