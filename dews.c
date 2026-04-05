#include "dews.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <arpa/inet.h>

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
    c->state = DEWS_STATE_OPEN;
    c->last_pong_received = time(NULL);
    c->waiting_pong = false;
    c->fragment_count = 0;
    c->current_opcode = 0;
    
    pthread_mutex_init(&c->lock, NULL);
    
    return c;
}

void dews_destroy(dews_client* c) {
    if (!c) return;
    
    pthread_mutex_lock(&c->lock);
    
    // Free fragments
    for (int i = 0; i < c->fragment_count; i++) {
        if (c->fragments[i].data) {
            free(c->fragments[i].data);
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
    
    uint8_t header[14];
    size_t hlen = 2;
    
    header[0] = 0x80 | (op & 0x0F);  // FIN bit set
    header[1] = 0x00;  // No mask from server
    
    if (len <= 125) {
        header[1] |= len;
    } else if (len <= 65535) {
        header[1] |= 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hlen = 4;
    } else {
        header[1] |= 127;
        for (int i = 0; i < 8; i++) {
            header[2 + i] = (len >> (56 - i * 8)) & 0xFF;
        }
        hlen = 10;
    }
    
    ssize_t sent = send(c->fd, header, hlen, MSG_NOSIGNAL);
    if (sent < 0 || (size_t)sent != hlen) return -1;
    
    if (len && payload) {
        sent = send(c->fd, payload, len, MSG_NOSIGNAL);
        if (sent < 0 || (size_t)sent != len) return -1;
    }
    
    return 0;
}

static int send_fragmented_frame(dews_client* c, uint8_t op, const uint8_t* data, uint64_t len) {
    if (!c || c->state != DEWS_STATE_OPEN) return -1;
    
    const uint64_t max_chunk = 16384;  // 16KB chunks
    uint64_t offset = 0;
    bool first = true;
    
    while (offset < len) {
        uint64_t chunk_size = len - offset;
        if (chunk_size > max_chunk) chunk_size = max_chunk;
        
        uint8_t header[14];
        size_t hlen = 2;
        
        uint8_t opcode = first ? op : DEWS_CONTINUATION;
        uint8_t fin = (offset + chunk_size >= len) ? 0x80 : 0x00;
        
        header[0] = fin | (opcode & 0x0F);
        header[1] = 0x00;  // No mask
        
        if (chunk_size <= 125) {
            header[1] |= chunk_size;
        } else if (chunk_size <= 65535) {
            header[1] |= 126;
            header[2] = (chunk_size >> 8) & 0xFF;
            header[3] = chunk_size & 0xFF;
            hlen = 4;
        } else {
            header[1] |= 127;
            for (int i = 0; i < 8; i++) {
                header[2 + i] = (chunk_size >> (56 - i * 8)) & 0xFF;
            }
            hlen = 10;
        }
        
        if (send(c->fd, header, hlen, MSG_NOSIGNAL) < 0) return -1;
        if (send(c->fd, data + offset, chunk_size, MSG_NOSIGNAL) < 0) return -1;
        
        offset += chunk_size;
        first = false;
    }
    
    return 0;
}

int dews_send_text(dews_client* c, const char* txt, uint64_t len) {
    if (!c || !txt || c->state != DEWS_STATE_OPEN) return -1;
    if (len == 0) len = strlen(txt);
    
    pthread_mutex_lock(&c->lock);
    int result;
    if (len > 16384) {
        result = send_fragmented_frame(c, DEWS_TEXT, (const uint8_t*)txt, len);
    } else {
        result = send_frame(c, DEWS_TEXT, (const uint8_t*)txt, len);
    }
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_binary(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || !data || c->state != DEWS_STATE_OPEN) return -1;
    
    pthread_mutex_lock(&c->lock);
    int result;
    if (len > 16384) {
        result = send_fragmented_frame(c, DEWS_BINARY, data, len);
    } else {
        result = send_frame(c, DEWS_BINARY, data, len);
    }
    pthread_mutex_unlock(&c->lock);
    
    return result;
}

int dews_send_ping(dews_client* c, const uint8_t* data, uint64_t len) {
    if (!c || c->state != DEWS_STATE_OPEN) return -1;
    if (len > 125) len = 125;  // Max payload for ping/pong
    
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
    if (len > 125) len = 125;
    
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
    
    pthread_mutex_unlock(&c->lock);
    
    return 0;
}

static int decode_frame(dews_client* c) {
    uint8_t* data = c->read_buf;
    size_t len = c->read_len;
    
    if (len < 2) return 0;
    
    uint8_t fin = (data[0] & 0x80) != 0;
    uint8_t op = data[0] & 0x0F;
    int masked = (data[1] & 0x80) != 0;
    uint64_t plen = data[1] & 0x7F;
    size_t hlen = 2;
    
    // Client MUST mask frames, server MUST NOT
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
    
    // Check frame size limit
    if (plen > DEWS_MAX_FRAME_SIZE) {
        if (c->on_error) c->on_error(c, "Frame too large");
        return -1;
    }
    
    if (len < hlen + 4) return 0;
    
    uint8_t mask[4];
    memcpy(mask, data + hlen, 4);
    hlen += 4;
    
    if (len < hlen + plen) return 0;
    
    uint8_t* payload = data + hlen;
    for (uint64_t i = 0; i < plen; i++) {
        payload[i] ^= mask[i % 4];
    }
    
    // Handle fragmented frames
    if (!fin) {
        if (op != DEWS_CONTINUATION && c->fragment_count == 0) {
            c->current_opcode = op;
        }
        
        if (c->fragment_count < DEWS_MAX_FRAGMENTED_FRAMES) {
            uint8_t* fragment_data = (uint8_t*)malloc(plen);
            if (fragment_data) {
                memcpy(fragment_data, payload, plen);
                c->fragments[c->fragment_count].data = fragment_data;
                c->fragments[c->fragment_count].len = plen;
                c->fragments[c->fragment_count].opcode = op;
                c->fragment_count++;
            }
        }
    } else {
        // Final frame - assemble message
        if (op == DEWS_CONTINUATION && c->fragment_count > 0) {
            // Calculate total size
            uint64_t total_len = plen;
            for (int i = 0; i < c->fragment_count; i++) {
                total_len += c->fragments[i].len;
            }
            
            uint8_t* assembled = (uint8_t*)malloc(total_len);
            if (assembled) {
                uint64_t offset = 0;
                for (int i = 0; i < c->fragment_count; i++) {
                    memcpy(assembled + offset, c->fragments[i].data, c->fragments[i].len);
                    offset += c->fragments[i].len;
                    free(c->fragments[i].data);
                    c->fragments[i].data = NULL;
                }
                memcpy(assembled + offset, payload, plen);
                
                if (c->on_msg) {
                    c->on_msg(c, c->current_opcode, assembled, total_len);
                }
                
                free(assembled);
            }
            c->fragment_count = 0;
            c->current_opcode = 0;
        } else if (op != DEWS_CONTINUATION) {
            // Single frame message
            if (c->on_msg) {
                c->on_msg(c, op, payload, plen);
            }
        }
    }
    
    // Handle control frames
    if (op == DEWS_PING) {
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
    
    // Send ping if needed
    if (!c->waiting_pong && (now - c->last_pong_received) >= DEWS_PING_INTERVAL) {
        dews_send_ping(c, (const uint8_t*)"ping", 4);
    }
    
    // Check for pong timeout
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
