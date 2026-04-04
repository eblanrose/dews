#ifndef DEWS_H
#define DEWS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define DEWS_BUFFER_SIZE 65536

typedef enum {
    DEWS_TEXT = 0x1,
    DEWS_BINARY = 0x2,
    DEWS_CLOSE = 0x8,
    DEWS_PING = 0x9,
    DEWS_PONG = 0xA
} dews_opcode;

typedef enum {
    DEWS_OPEN,
    DEWS_CLOSED
} dews_state;

typedef struct dews_client {
    int fd;
    dews_state state;
    void* userdata;
    uint8_t read_buf[DEWS_BUFFER_SIZE];
    size_t read_len;
    void (*on_msg)(struct dews_client* c, uint8_t op, uint8_t* data, uint64_t len);
    void (*on_close)(struct dews_client* c, uint16_t code, const char* reason);
} dews_client;

dews_client* dews_create(int fd);
void dews_set_callbacks(dews_client* c, void (*on_msg)(dews_client*, uint8_t, uint8_t*, uint64_t), void (*on_close)(dews_client*, uint16_t, const char*));
int dews_send_text(dews_client* c, const char* txt, uint64_t len);
int dews_send_binary(dews_client* c, const uint8_t* data, uint64_t len);
int dews_send_close(dews_client* c, uint16_t code, const char* reason);
void dews_process(dews_client* c);
void dews_close(dews_client* c);
void dews_free(dews_client* c);
void dews_gen_accept_key(const char* key, char* out, size_t out_len);

#endif
