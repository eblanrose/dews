#include "dews.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void dews_gen_accept_key(const char* key, char* out, size_t out_len) {
    if (!key || !out || out_len < 29) {
        if (out && out_len) out[0] = '\0';
        return;
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "%s%s", key, WS_GUID);
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)buf, strlen(buf), hash);
    EVP_EncodeBlock((unsigned char*)out, hash, SHA_DIGEST_LENGTH);
    out[28] = '\0';
}

dews_client* dews_create(int fd) {
    dews_client* c = (dews_client*)calloc(1, sizeof(dews_client));
    if (!c) return NULL;
    c->fd = fd;
    c->state = DEWS_OPEN;
    return c;
}

void dews_set_callbacks(dews_client* c, void (*on_msg)(dews_client*, uint8_t, uint8_t*, uint64_t), void (*on_close)(dews_client*, uint16_t, const char*)) {
    if (!c) return;
    c->on_msg = on_msg;
    c->on_close = on_close;
}

static int send_frame(dews_client* c, uint8_t op, const uint8_t* payload, uint64_t len) {
    if (!c || c->state != DEWS_OPEN) return -1;
    uint8_t header[14];
    size_t hlen = 2;
    header[0] = 0x80 | op;
    header[1] = 0x00;
    if (len <= 125) {
        header[1] |= len;
    } else if (len <= 65535) {
        header[1] |= 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hlen = 4;
    } else {
        header[1] |= 127;
        for (int i = 0; i < 8; i++)
            header[2 + i] = (len >> (56 - i * 8)) & 0xFF;
        hlen = 10;
    }
    if (send(c->fd, header, hlen, MSG_NOSIGNAL) < 0) return -1;
    if (len && payload && send(c->fd, payload, len, MSG_NOSIGNAL) < 0) return -1;
    return 0;
}

int dews_send_text(dews_client* c, const char* txt, uint64_t len) {
    if (!c || !txt || c->state != DEWS_OPEN) return -1;
    if (len == 0) len = strlen(txt);
    return send_frame(c, DEWS_TEXT, (const uint8_t*)txt, len);
}

int dews_send_binary(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || !data || c->state != DEWS_OPEN) return -1;
    return send_frame(c, DEWS_BINARY, data, len);
}

int dews_send_close(dews_client* c, uint16_t code, const char* reason) {
    if (!c) return -1;
    uint8_t buf[128];
    size_t len = 0;
    if (code) {
        buf[len++] = (code >> 8) & 0xFF;
        buf[len++] = code & 0xFF;
    }
    if (reason) {
        size_t rlen = strlen(reason);
        if (rlen > sizeof(buf) - len - 1) rlen = sizeof(buf) - len - 1;
        memcpy(buf + len, reason, rlen);
        len += rlen;
    }
    send_frame(c, DEWS_CLOSE, buf, len);
    c->state = DEWS_CLOSED;
    return 0;
}

static int decode_frame(dews_client* c) {
    uint8_t* data = c->read_buf;
    size_t len = c->read_len;
    if (len < 2) return 0;
    
    uint8_t op = data[0] & 0x0F;
    int masked = (data[1] & 0x80) != 0;
    uint64_t plen = data[1] & 0x7F;
    size_t hlen = 2;
    
    if (plen == 126) {
        if (len < 4) return 0;
        plen = (data[2] << 8) | data[3];
        hlen = 4;
    } else if (plen == 127) {
        if (len < 10) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | data[2 + i];
        hlen = 10;
    }
    
    if (!masked) return 0;
    if (len < hlen + 4) return 0;
    uint8_t mask[4];
    memcpy(mask, data + hlen, 4);
    hlen += 4;
    if (len < hlen + plen) return 0;
    
    uint8_t* payload = data + hlen;
    for (uint64_t i = 0; i < plen; i++) payload[i] ^= mask[i % 4];
    
    if (c->on_msg && (op == DEWS_TEXT || op == DEWS_BINARY))
        c->on_msg(c, op, payload, plen);
    else if (op == DEWS_PING)
        send_frame(c, DEWS_PONG, payload, plen);
    else if (op == DEWS_CLOSE) {
        uint16_t code = 1000;
        const char* reason = NULL;
        if (plen >= 2) code = (payload[0] << 8) | payload[1];
        if (plen > 2) reason = (const char*)(payload + 2);
        if (c->on_close) c->on_close(c, code, reason);
        c->state = DEWS_CLOSED;
    }
    
    size_t consumed = hlen + plen;
    if (consumed < c->read_len) {
        memmove(c->read_buf, c->read_buf + consumed, c->read_len - consumed);
        c->read_len -= consumed;
    } else {
        c->read_len = 0;
    }
    return 1;
}

void dews_process(dews_client* c) {
    if (!c) return;
    ssize_t n = recv(c->fd, c->read_buf + c->read_len, DEWS_BUFFER_SIZE - c->read_len - 1, MSG_DONTWAIT);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            if (c->on_close) c->on_close(c, 1006, n == 0 ? "Closed" : "Lost");
            c->state = DEWS_CLOSED;
        }
        return;
    }
    c->read_len += n;
    while (c->read_len >= 2 && decode_frame(c));
}

void dews_close(dews_client* c) {
    if (!c) return;
    if (c->state == DEWS_OPEN) dews_send_close(c, 1000, "Normal");
    close(c->fd);
    c->state = DEWS_CLOSED;
}

void dews_free(dews_client* c) {
    if (c) free(c);
}
