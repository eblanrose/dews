#ifndef DEWS_H
#define DEWS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>

#define DEWS_BUFFER_SIZE 65536
#define DEWS_MAX_FRAME_SIZE 16777216
#define DEWS_PING_INTERVAL 30
#define DEWS_PONG_TIMEOUT 10
#define DEWS_MAX_FRAGMENTED_FRAMES 16
#define DEWS_MAX_PAYLOAD_SIZE 125

typedef enum {
    DEWS_CONTINUATION = 0x0,
    DEWS_TEXT = 0x1,
    DEWS_BINARY = 0x2,
    DEWS_CLOSE = 0x8,
    DEWS_PING = 0x9,
    DEWS_PONG = 0xA
} dews_opcode;

typedef enum {
    DEWS_STATE_OPEN,
    DEWS_STATE_CLOSING,
    DEWS_STATE_CLOSED
} dews_state;

typedef struct dews_fragment {
    uint8_t* data;
    uint64_t len;
    uint8_t opcode;
} dews_fragment;

typedef struct dews_client {
    int fd;
    dews_state state;
    void* userdata;
    uint8_t read_buf[DEWS_BUFFER_SIZE];
    size_t read_len;
    uint8_t write_buf[DEWS_BUFFER_SIZE];
    size_t write_len;
    
    dews_fragment fragments[DEWS_MAX_FRAGMENTED_FRAMES];
    int fragment_count;
    uint8_t current_opcode;
    
    time_t last_ping_sent;
    time_t last_pong_received;
    bool waiting_pong;
    
    pthread_mutex_t lock;
    
    void (*on_open)(struct dews_client* c);
    void (*on_msg)(struct dews_client* c, uint8_t op, uint8_t* data, uint64_t len);
    void (*on_close)(struct dews_client* c, uint16_t code, const char* reason);
    void (*on_error)(struct dews_client* c, const char* error);
    void (*on_ping)(struct dews_client* c, uint8_t* data, uint64_t len);
    void (*on_pong)(struct dews_client* c, uint8_t* data, uint64_t len);
} dews_client;

dews_client* dews_create(int fd);
void dews_destroy(dews_client* c);
void dews_set_callbacks(dews_client* c, 
    void (*on_open)(dews_client*),
    void (*on_msg)(dews_client*, uint8_t, uint8_t*, uint64_t),
    void (*on_close)(dews_client*, uint16_t, const char*),
    void (*on_error)(dews_client*, const char*));
void dews_set_ping_callbacks(dews_client* c,
    void (*on_ping)(dews_client*, uint8_t*, uint64_t),
    void (*on_pong)(dews_client*, uint8_t*, uint64_t));
int dews_send_text(dews_client* c, const char* txt, uint64_t len);
int dews_send_binary(dews_client* c, const uint8_t* data, uint64_t len);
int dews_send_ping(dews_client* c, const uint8_t* data, uint64_t len);
int dews_send_pong(dews_client* c, const uint8_t* data, uint64_t len);
int dews_send_close(dews_client* c, uint16_t code, const char* reason);
int dews_process(dews_client* c);
int dews_process_write(dews_client* c);
void dews_timer_update(dews_client* c);
void dews_gen_accept_key(const char* key, char* out, size_t out_len);
void dews_close(dews_client* c);
bool dews_is_open(const dews_client* c);

#endif
