#include "web_socket.h"

#define WS_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WS_ANSWER	\
"HTTP/1.1 101 Switching Protocols\r\n"	\
"Upgrade: websocket\r\n"	\
"Connection: Upgrade\r\n"	\
"Sec-WebSocket-Accept: %s\r\n"	\
"\r\n"

#define WS_PARSE	\
"GET %s HTTP/1.1\r\n"	\
"Host: %s\r\n"	\
"Upgrade: websocket\r\n"	\
"Connection: Upgrade\r\n"	\
"Origin: http://coolaf.com\r\n"	\
"Sec-WebSocket-Version: 13\r\n"	\
"Sec-WebSocket-Key: %s\r\n"	\
"\r\n"

int ws_new(ws_handle* ws, int mask, size_t size)
{
	ws->Mask = mask;
	ws->buf = (char*)malloc(size);
	ws->capacity = size;
	if (!ws->buf)
		return -1;
	return 0;
}

int ws_delete(ws_handle ws)
{
	free(ws.buf);
	return 0;
}

int ws_accept(ws_handle* ws, char* input, size_t size)
{
	char key[64] = { 0 };
	char* in_key = strstr(input, "Sec-WebSocket-Key: ");
	if (!key)
		return -1;

	in_key += strlen("Sec-WebSocket-Key: ");
	int key_len = strchr(in_key, '\r') - in_key;
	if (key_len > 24)
		return -2;

	memcpy(key, in_key, strchr(in_key, '\r') - in_key);
	memcpy(key + strlen(key), WS_KEY, strlen(WS_KEY));

	uint32_t hash[5];
	SHA_CTX s;
	SHA1_Init(&s);
	SHA1_Update(&s, key, strlen(key));
	SHA1_Final((unsigned char*)hash, &s);

	base64_encode((char*)hash, 20, key);
	sprintf(ws->buf, WS_ANSWER, key);

	ws->size = strlen(ws->buf);
	return 0;
}

int ws_upgrade(ws_handle* ws, const char* host, const char* get)
{
	char key[18];
	srand(time(NULL));
	for (int i = 0; i < 18; ++i)
		key[i] = rand() % 0x1ffff;
	char base64_key[25];
	base64_encode(key, 18, base64_key);
	sprintf(ws->buf, WS_PARSE, get, host, base64_key);
	ws->size = strlen(ws->buf);
	return 0;
}

int ws_read(ws_handle* ws, char* input, size_t size)
{
	ws->len = 0;
	frame f;
	uint64_t u_len = 2;
	size_t ws_buf_len = ws->capacity;
	char* ws_buf = ws->buf;
	if (size < u_len)
		return -1;

	int ret = f.Opcode = input[0] & 0xf;

	do
	{
		u_len = 2;
		if (size < u_len)
			return -1;

		f.FIN = (input[0] & 0x80) >> 7;
		f.RSV1 = (input[0] & 0x40) >> 6;
		f.RSV2 = (input[0] & 0x20) >> 5;
		f.RSV3 = (input[0] & 0x10) >> 4;
		f.Opcode = input[0] & 0xf;

		f.MASK = (input[1] & 0x80) >> 7;
		f.Payload_len = input[1] & 0x7f;

		input = &input[2];

		if (f.Payload_len < 126)
		{
			f.Payload_len_continued = f.Payload_len;
			if (ws_buf_len < f.Payload_len_continued)
				return -1;
		}
		else if (f.Payload_len == 126)
		{
			u_len += 2;
			if (size < u_len || ws_buf_len < f.Payload_len)
				return -1;
			uint16_t data_len_t = *(uint16_t*)input;
			NTOH(uint16_t, data_len_t);
			f.Payload_len_continued = data_len_t;
			input = &input[2];
		}
		else if (f.Payload_len == 127)
		{
			u_len += 8;
			if (size < u_len || ws_buf_len < f.Payload_len)
				return -1;
			uint64_t data_len_t = *(uint64_t*)input;
			NTOH(uint64_t, data_len_t);
			f.Payload_len_continued = data_len_t;
		}

		if (f.MASK == 1)
		{
			if (ws->Mask != WS_ALL_MASK && ws->Mask != WS_READ_MASK)
				return -2;

			u_len += (4 + f.Payload_len_continued);
			if (size < u_len)
				return -1;
			f.Mask_key[0] = input[0];
			f.Mask_key[1] = input[1];
			f.Mask_key[2] = input[2];
			f.Mask_key[3] = input[3];
			input = &input[4];

			for (int c = 0; c < f.Payload_len_continued; ++c)
			{
				ws_buf[c] = (input[c]) ^ (f.Mask_key[c % 4]);
			}
		}
		else
		{
			memcpy(ws_buf, input, f.Payload_len_continued);
		}
		ws_buf_len -= f.Payload_len_continued;
		ws->size += f.Payload_len_continued;
		ws_buf += f.Payload_len_continued;
		input = &input[f.Payload_len_continued - 1];
		size -= u_len;
	} while (!f.FIN);
	return 	ret;
}

int ws_write(ws_handle* ws, char* input, size_t size, uint8_t fin, uint8_t opcode)
{
	ws->len = 0;
	frame f;
	uint64_t u_len = 2;
	size_t ws_buf_len = ws->capacity;
	if (ws_buf_len < u_len)
		return -1;
	char* f_buf = ws->buf;
	char* buf = ws->buf;
	if (size < 126)
	{
		f.Payload_len = size;
		f.Payload_len_continued = size;
		u_len += size;
		buf[1] = f.Payload_len;
		buf = &buf[2];
	}
	else if (size <= 0xffff)
	{
		f.Payload_len = 126;
		f.Payload_len_continued = size;
		u_len += size + 2;
		buf[1] = 126;
		uint8_t t_size = size;
		HTON(uint8_t, t_size);
		*(uint8_t*)& buf[2] = t_size;
		buf = &buf[4];
	}
	else
	{
		f.Payload_len = 127;
		f.Payload_len_continued = size;
		u_len += size + 8;
		buf[1] = 127;
		uint64_t t_size = size;
		HTON(uint64_t, t_size);
		*(uint64_t*)& buf[2] = t_size;
		buf = &buf[10];
	}

	if (ws->Mask == WS_WRITE_MASK || ws->Mask == WS_ALL_MASK)
	{
		u_len += 4;
		f_buf[1] = f_buf[1] | 0x80;
		srand(time(NULL));
		for (int i = 0; i < 4; ++i)
		{
			buf[i] = rand() % 0x1ffff;
			f.Mask_key[i] = buf[i];
		}
		buf = &buf[4];
		for (int i = 0; i < f.Payload_len_continued; ++i)
		{
			buf[i] = (input[i]) ^ (f.Mask_key[i % 4]);
		}
	}
	else
	{
		f_buf[1] = f_buf[1] & 0x7f;
		memcpy(buf, input, f.Payload_len_continued);
	}
	f_buf[0] = (fin << 7) | opcode;
	ws->size = u_len;
	return 	0;
}

int base64_encode(char* in_str, int in_len, char* out_str)
{
	BIO* b64, * bio;
	BUF_MEM* bptr = NULL;
	size_t size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, in_str, in_len);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	memcpy(out_str, bptr->data, bptr->length);
	out_str[bptr->length - 1] = '\0';
	size = bptr->length - 1;

	BIO_free_all(bio);
	return size;
}

int base64_decode(char* in_str, int in_len, char* out_str)
{
	BIO* b64, * bio;
	BUF_MEM* bptr = NULL;
	int counts;
	int size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(in_str, in_len);
	bio = BIO_push(b64, bio);

	size = BIO_read(bio, out_str, in_len);
	out_str[size] = '\0';

	BIO_free_all(bio);
	return size;
}
