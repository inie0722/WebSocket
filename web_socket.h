#pragma once

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define WS_ALL_MASK 0X1
#define WS_READ_MASK 0X2
#define WS_WRITE_MASK 0X3

#define WS_TYPE_ADDITIONAL_DATA 0X1
#define WS_TYPE_TEXT 0X2
#define WS_TYPE_BINARY 0X3
#define WS_TYPE_CLOSE 0X8
#define WS_TYPE_PING 0X9
#define WS_TYPE_PONG 0XA;

#define WS_FIN_CON 0
#define WS_FIN_END 1

#define HTON(type, h)   \
        do      \
        {       \
                int _i = 1;     \
                if (*(char*)& _i != 1)  \
                        break;  \
        \
                type _n;        \
                for (unsigned int _t = 0; _t < sizeof(type); ++_t)      \
                {       \
                        ((char*)& _n)[_t] = ((char*)& h)[ sizeof(type) - _t - 1];       \
                }       \
                h = _n; \
        }while(0);

#define NTOH(type, n)   \
        do      \
        {       \
                int _i = 1;     \
                if (*(char*)& _i != 1)  \
                        break;  \
        \
                type _h;        \
                for (unsigned int _t = 0; _t < sizeof(type); ++_t)      \
                {       \
                        ((char*)& _h)[_t] = ((char*)& n)[ sizeof(type) - _t - 1];       \
                }       \
                n = _h; \
        }while(0);


typedef struct frame
{
	uint8_t FIN : 1;
	uint8_t RSV1 : 1;
	uint8_t RSV2 : 1;
	uint8_t RSV3 : 1;
	uint8_t Opcode : 4;
	uint8_t MASK : 1;
	uint8_t Payload_len : 7;
	uint64_t Payload_len_continued;
	uint8_t Mask_key[4];
}frame;

typedef struct ws_handle
{
	uint8_t Mask;
	char* buf;
	size_t size;
	size_t capacity;
}ws_handle;

int ws_new(ws_handle* ws, int mask, size_t size);

int ws_delete(ws_handle ws);

int ws_accept(ws_handle* ws, char* input, size_t size);

int ws_upgrade(ws_handle* ws, const char* host, const char* get);

int ws_read(ws_handle* ws, char* input, size_t size);

int ws_write(ws_handle* ws, char* input, size_t size, uint8_t fin, uint8_t opcode);

int base64_encode(char* in_str, int in_len, char* out_str);

int base64_decode(char* in_str, int in_len, char* out_str);