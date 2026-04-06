#include "dews.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <limits.h>

static const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static size_t safe_strlen(const char* s, size_t max_len) {
    if (!s) return 0;
    size_t len = 0;
    while (len < max_len && s[len]) len++;
    return len;
}

static int safe_memcpy(void* dest, size_t dest_size, const void* src, size_t src_len) {
    if (!dest || !src || dest_size == 0) return -1;
    if (src_len > dest_size) return -1;
    memcpy(dest, src, src_len);
    return 0;
}

static int safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) return -1;
    size_t src_len = safe_strlen(src, dest_size - 1);
    if (safe_memcpy(dest, dest_size, src, src_len) != 0) return -1;
    dest[src_len] = '\0';
    return 0;
}

void dews_gen_accept_key(const char* key, char* out, size_t out_len) {
    if (!key || !out || out_len < 29) {
        if (out && out_len) out[0] = '\0';
        return;
    }
    
    char buf[256];
    size_t key_len = safe_strlen(key, sizeof(buf) - 37);
    if (key_len + 36 >= sizeof(buf)) {
        out[0] = '\0';
        return;
    }
    
    memcpy(buf, key, key_len);
    memcpy(buf + key_len, WS_GUID, 36);
    size_t total_len = key_len + 36;
    buf[total_len] = '\0';
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)buf, total_len, hash);
    
    EVP_EncodeBlock((unsigned char*)out, hash, SHA_DIGEST_LENGTH);
    out[28] = '\0';
}

dews_client* dews_create(int fd) {
    dews_client* c = (dews_client*)calloc(1, sizeof(dews_client));
    if (!c) return NULL;
    
    c->fd = fd;
    c->state = DEWS_STATE_OPEN;
    c->last_pong_received = time(NULL);
    c->waiting_pong = false;
    c->fragment_count = 0;
    c->current_opcode = 0;
    c->read_len = 0;
    c->write_len = 0;
    
    pthread_mutex_init(&c->lock, NULL);
    
    return c;
}

void dews_destroy(dews_client* c) {
    if (!c) return;
    
    pthread_mutex_lock(&c->lock);
    
    for (int i = 0; i < c->fragment_count; i++) {
        if (c->fragments[i].data) {
            free(c->fragments[i].data);
            c->fragments[i].data = NULL;
        }
    }
    
    pthread_mutex_unlock(&c->lock);
    pthread_mutex_destroy(&c->lock);
    
    free(c);
}

void dews_set_callbacks(dews_client* c, 
    void (*on_open)(dews_client*),
    void (*on_msg)(dews_client*, uint8_t, uint8_t*, uint64_t),
    void (*on_close)(dews_client*, uint16_t, const char*),
    void (*on_error)(dews_client*, const char*)) {
    
    if (!c) return;
    
    pthread_mutex_lock(&c->lock);
    c->on_open = on_open;
    c->on_msg = on_msg;
    c->on_close = on_close;
    c->on_error = on_error;
    pthread_mutex_unlock(&c->lock);
    
    if (on_open) on_open(c);
}

void dews_set_ping_callbacks(dews_client* c,
    void (*on_ping)(dews_client*, uint8_t*, uint64_t),
    void (*on_pong)(dews_client*, uint8_t*, uint64_t)) {
    
    if (!c) return;
    
    pthread_mutex_lock(&c->lock);
    c->on_ping = on_ping;
    c->on_pong = on_pong;
    pthread_mutex_unlock(&c->lock);
}

static int send_frame(dews_client* c, uint8_t op, const uint8_t* payload, uint64_t len) {
    if (!c || c->state != DEWS_STATE_OPEN) return -1;
    if (len > DEWS_MAX_FRAME_SIZE) return -1;
    
    uint8_t header[14];
    size_t hlen = 2;
    
    header[0] = 0x80 | (op & 0x0F);
    header[1] = 0x00;
    
    if (len <= 125) {
        header[1] |= (uint8_t)len;
    } else if (len <= 65535) {
        header[1] |= 126;
        header[2] = (uint8_t)((len >> 8) & 0xFF);
        header[3] = (uint8_t)(len & 0xFF);
        hlen = 4;
    } else {
        header[1] |= 127;
        for (int i = 0; i < 8; i++) {
            header[2 + i] = (uint8_t)((len >> (56 - i * 8)) & 0xFF);
        }
        hlen = 10;
    }
    
    ssize_t sent = send(c->fd, header, hlen, MSG_NOSIGNAL);
    if (sent < 0 || (size_t)sent != hlen) return -1;
    
    if (len > 0 && payload) {
        sent = send(c->fd, payload, len, MSG_NOSIGNAL);
        if (sent < 0 || (size_t)sent != len) return -1;
    }
    
    return 0;
}

int dews_send_text(dews_client* c, const char* txt, uint64_t len) {
    if (!c || !txt || c->state != DEWS_STATE_OPEN) return -1;
    if (len == 0) len = safe_strlen(txt, DEWS_MAX_FRAME_SIZE);
    if (len > DEWS_MAX_FRAME_SIZE) return -1;
    
    pthread_mutex_lock(&c->lock);
    int result = send_frame(c, DEWS_TEXT, (const uint8_t*)txt, len);
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_binary(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || !data || c->state != DEWS_STATE_OPEN) return -1;
    if (len > DEWS_MAX_FRAME_SIZE) return -1;
    
    pthread_mutex_lock(&c->lock);
    int result = send_frame(c, DEWS_BINARY, data, len);
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_ping(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || c->state != DEWS_STATE_OPEN) return -1;
    if (len > DEWS_MAX_PAYLOAD_SIZE) len = DEWS_MAX_PAYLOAD_SIZE;
    
    pthread_mutex_lock(&c->lock);
    int result = send_frame(c, DEWS_PING, data, len);
    if (result == 0) {
        c->last_ping_sent = time(NULL);
        c->waiting_pong = true;
    }
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_pong(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || c->state != DEWS_STATE_OPEN) return -1;
    if (len > DEWS_MAX_PAYLOAD_SIZE) len = DEWS_MAX_PAYLOAD_SIZE;
    
    pthread_mutex_lock(&c->lock);
    int result = send_frame(c, DEWS_PONG, data, len);
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_close(dews_client* c, uint16_t code, const char* reason) {
    if (!c) return -1;
    
    pthread_mutex_lock(&c->lock);
    
    if (c->state != DEWS_STATE_OPEN) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    
    c->state = DEWS_STATE_CLOSING;
    
    uint8_t buf[128];
    size_t len = 0;
    
    if (code != 0) {
        buf[len++] = (uint8_t)((code >> 8) & 0xFF);
        buf[len++] = (uint8_t)(code & 0xFF);
    }
    
    if (reason && len < sizeof(buf) - 1) {
        size_t rlen = safe_strlen(reason, sizeof(buf) - len - 1);
        if (safe_memcpy(buf + len, sizeof(buf) - len, reason, rlen) == 0) {
            len += rlen;
        }
    }
    
    send_frame(c, DEWS_CLOSE, buf, len);
    
    pthread_mutex_unlock(&c->lock);
    
    return 0;
}

static int decode_frame(dews_client* c) {
    if (!c || c->read_len < 2) return 0;
    
    uint8_t* data = c->read_buf;
    size_t len = c->read_len;
    
    uint8_t fin = (data[0] & 0x80) != 0;
    uint8_t op = data[0] & 0x0F;
    int masked = (data[1] & 0x80) != 0;
    uint64_t plen = data[1] & 0x7F;
    size_t hlen = 2;
    
    if (!masked) {
        if (c->on_error) c->on_error(c, "Unmasked frame from client");
        return -1;
    }
    
    if (plen == 126) {
        if (len < 4) return 0;
        plen = (data[2] << 8) | data[3];
        hlen = 4;
    } else if (plen == 127) {
        if (len < 10) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) {
            plen = (plen << 8) | data[2 + i];
        }
        hlen = 10;
    }
    
    if (plen > DEWS_MAX_FRAME_SIZE) {
        if (c->on_error) c->on_error(c, "Frame too large");
        return -1;
    }
    
    if (len < hlen + 4) return 0;
    
    uint8_t mask[4];
    if (safe_memcpy(mask, sizeof(mask), data + hlen, 4) != 0) return -1;
    hlen += 4;
    
    if (len < hlen + plen) return 0;
    
    uint8_t* payload = data + hlen;
    for (uint64_t i = 0; i < plen; i++) {
        payload[i] ^= mask[i % 4];
    }
    
    if (!fin) {
        if (op != DEWS_CONTINUATION && c->fragment_count == 0) {
            c->current_opcode = op;
        }
        
        if (c->fragment_count < DEWS_MAX_FRAGMENTED_FRAMES && plen > 0) {
            uint8_t* fragment_data = (uint8_t*)malloc(plen);
            if (fragment_data) {
                if (safe_memcpy(fragment_data, plen, payload, plen) == 0) {
                    c->fragments[c->fragment_count].data = fragment_data;
                    c->fragments[c->fragment_count].len = plen;
                    c->fragments[c->fragment_count].opcode = op;
                    c->fragment_count++;
                } else {
                    free(fragment_data);
                }
            }
        }
    } else {
        if (op == DEWS_CONTINUATION && c->fragment_count > 0) {
            uint64_t total_len = plen;
            for (int i = 0; i < c->fragment_count; i++) {
                total_len += c->fragments[i].len;
            }
            
            if (total_len <= DEWS_MAX_FRAME_SIZE) {
                uint8_t* assembled = (uint8_t*)malloc(total_len);
                if (assembled) {
                    uint64_t offset = 0;
                    int valid = 1;
                    
                    for (int i = 0; i < c->fragment_count && valid; i++) {
                        if (safe_memcpy(assembled + offset, total_len - offset,
                                       c->fragments[i].data, c->fragments[i].len) == 0) {
                            offset += c->fragments[i].len;
                        } else {
                            valid = 0;
                        }
                        free(c->fragments[i].data);
                        c->fragments[i].data = NULL;
                    }
                    
                    if (valid && safe_memcpy(assembled + offset, total_len - offset,
                                            payload, plen) == 0) {
                        if (c->on_msg) {
                            c->on_msg(c, c->current_opcode, assembled, total_len);
                        }
                    }
                    
                    free(assembled);
                }
            }
            
            c->fragment_count = 0;
            c->current_opcode = 0;
        } else if (op != DEWS_CONTINUATION && plen > 0) {
            if (c->on_msg) {
                uint8_t* msg_data = (uint8_t*)malloc(plen);
                if (msg_data) {
                    if (safe_memcpy(msg_data, plen, payload, plen) == 0) {
                        c->on_msg(c, op, msg_data, plen);
                    }
                    free(msg_data);
                }
            }
        }
    }
    
    if (op == DEWS_PING) {
        if (plen > DEWS_MAX_PAYLOAD_SIZE) plen = DEWS_MAX_PAYLOAD_SIZE;
        dews_send_pong(c, payload, plen);
        if (c->on_ping) c->on_ping(c, payload, plen);
    } else if (op == DEWS_PONG) {
        c->last_pong_received = time(NULL);
        c->waiting_pong = false;
        if (c->on_pong) c->on_pong(c, payload, plen);
    } else if (op == DEWS_CLOSE) {
        uint16_t code = 1000;
        const char* reason = NULL;
        if (plen >= 2) {
            code = (payload[0] << 8) | payload[1];
        }
        if (plen > 2) {
            reason = (const char*)(payload + 2);
        }
        
        if (c->on_close) c->on_close(c, code, reason);
        c->state = DEWS_STATE_CLOSED;
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

int dews_process(dews_client* c) {
    if (!c) return -1;
    
    pthread_mutex_lock(&c->lock);
    
    if (c->state == DEWS_STATE_CLOSED) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    
    if (c->read_len >= DEWS_BUFFER_SIZE - 1) {
        if (c->on_error) c->on_error(c, "Read buffer full");
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    
    ssize_t n = recv(c->fd, c->read_buf + c->read_len, 
                     DEWS_BUFFER_SIZE - c->read_len - 1, MSG_DONTWAIT);
    
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            if (c->on_close) {
                pthread_mutex_unlock(&c->lock);
                c->on_close(c, 1006, n == 0 ? "Connection closed" : "Connection lost");
                pthread_mutex_lock(&c->lock);
            }
            c->state = DEWS_STATE_CLOSED;
            pthread_mutex_unlock(&c->lock);
            return -1;
        }
        pthread_mutex_unlock(&c->lock);
        return 0;
    }
    
    c->read_len += n;
    c->read_buf[c->read_len] = '\0';
    
    int result = 0;
    while (c->read_len >= 2 && result >= 0) {
        result = decode_frame(c);
        if (result < 0) break;
    }
    
    pthread_mutex_unlock(&c->lock);
    return result >= 0 ? 0 : -1;
}

int dews_process_write(dews_client* c) {
    if (!c) return -1;
    
    pthread_mutex_lock(&c->lock);
    
    if (c->write_len > 0) {
        ssize_t sent = send(c->fd, c->write_buf, c->write_len, MSG_NOSIGNAL);
        if (sent > 0) {
            if ((size_t)sent < c->write_len) {
                memmove(c->write_buf, c->write_buf + sent, c->write_len - sent);
                c->write_len -= sent;
            } else {
                c->write_len = 0;
            }
        }
    }
    
    pthread_mutex_unlock(&c->lock);
    return 0;
}

void dews_timer_update(dews_client* c) {
    if (!c || c->state != DEWS_STATE_OPEN) return;
    
    time_t now = time(NULL);
    
    pthread_mutex_lock(&c->lock);
    
    if (!c->waiting_pong && (now - c->last_pong_received) >= DEWS_PING_INTERVAL) {
        dews_send_ping(c, (const uint8_t*)"ping", 4);
    }
    
    if (c->waiting_pong && (now - c->last_ping_sent) >= DEWS_PONG_TIMEOUT) {
        if (c->on_error) c->on_error(c, "Pong timeout");
        c->state = DEWS_STATE_CLOSED;
        if (c->on_close) c->on_close(c, 1006, "Pong timeout");
    }
    
    pthread_mutex_unlock(&c->lock);
}

void dews_close(dews_client* c) {
    if (!c) return;
    
    pthread_mutex_lock(&c->lock);
    
    if (c->state == DEWS_STATE_OPEN) {
        dews_send_close(c, 1000, "Normal closure");
    }
    
    shutdown(c->fd, SHUT_RDWR);
    close(c->fd);
    c->state = DEWS_STATE_CLOSED;
    
    pthread_mutex_unlock(&c->lock);
}

bool dews_is_open(const dews_client* c) {
    if (!c) return false;
    return c->state == DEWS_STATE_OPEN;
}
