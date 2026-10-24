#define _GNU_SOURCE
#include "bank.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

int send_all(int fd, const void *data, size_t length)
{
    const unsigned char *cursor = data;
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(fd, cursor + sent, length - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        sent += (size_t)count;
    }
    return 0;
}

int send_line(int fd, const char *line)
{
    size_t length = strlen(line);
    if (send_all(fd, line, length) < 0)
        return -1;
    return send_all(fd, "\n", 1);
}

ssize_t recv_line(int fd, char *buffer, size_t capacity)
{
    if (capacity < 2)
        return -1;
    size_t used = 0;
    int overflow = 0;
    for (;;) {
        char byte;
        ssize_t count = recv(fd, &byte, 1, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (used == 0)
                return count;
            break;
        }
        if (byte == '\n')
            break;
        if (byte == '\r')
            continue;
        if (used + 1 < capacity)
            buffer[used++] = byte;
        else
            overflow = 1;
    }
    buffer[used] = '\0';
    return overflow ? -2 : (ssize_t)used;
}

int send_reply(int fd, const char *line)
{
    if (send_line(fd, line) < 0)
        return -1;
    return send_line(fd, ".");
}

int split_fields(char *line, char **fields, int capacity)
{
    if (capacity <= 0)
        return -1;
    int count = 1;
    fields[0] = line;
    for (char *cursor = line; *cursor != '\0'; cursor++) {
        if (*cursor == '|') {
            *cursor = '\0';
            if (count == capacity)
                return -1;
            fields[count++] = cursor + 1;
        }
    }
    return count;
}

int parse_money(const char *text, int64_t *cents)
{
    if (text == NULL || *text == '\0' || cents == NULL)
        return -1;
    int64_t whole = 0;
    int fractional = 0;
    int digits = 0;
    int decimal = 0;
    int decimals = 0;
    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        if (*cursor == '.' && !decimal) {
            decimal = 1;
            continue;
        }
        if (*cursor < '0' || *cursor > '9')
            return -1;
        int digit = *cursor - '0';
        digits++;
        if (!decimal) {
            if (whole > (INT64_MAX / 100 - digit) / 10)
                return -1;
            whole = whole * 10 + digit;
        } else {
            if (decimals == 2)
                return -1;
            fractional = fractional * 10 + digit;
            decimals++;
        }
    }
    if (digits == 0)
        return -1;
    if (decimals == 1)
        fractional *= 10;
    if (whole > (INT64_MAX - fractional) / 100)
        return -1;
    *cents = whole * 100 + fractional;
    return 0;
}

void format_money(int64_t cents, char *buffer, size_t capacity)
{
    if (cents < 0)
        cents = 0;
    long long whole = (long long)(cents / 100);
    long long fraction = (long long)(cents % 100);
    (void)snprintf(buffer, capacity, "%lld.%02lld", whole, fraction);
}

int parse_u32(const char *text, uint32_t *value)
{
    if (text == NULL || *text == '\0' || value == NULL)
        return -1;
    uint64_t result = 0;
    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return -1;
        result = result * 10 + (uint64_t)(*cursor - '0');
        if (result > UINT32_MAX)
            return -1;
    }
    if (result == 0)
        return -1;
    *value = (uint32_t)result;
    return 0;
}

int lock_range(int fd, short type, off_t start, off_t length)
{
    struct flock range;
    memset(&range, 0, sizeof(range));
    range.l_type = type;
    range.l_whence = SEEK_SET;
    range.l_start = start;
    range.l_len = length;
    int command = type == F_UNLCK ? F_OFD_SETLK : F_OFD_SETLKW;
    for (;;) {
        if (fcntl(fd, command, &range) == 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}

int pread_full(int fd, void *buffer, size_t length, off_t offset)
{
    unsigned char *cursor = buffer;
    size_t received = 0;
    while (received < length) {
        ssize_t count = pread(fd, cursor + received, length - received, offset + (off_t)received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            return -1;
        if (count == 0)
            return received == 0 ? 1 : -1;
        received += (size_t)count;
    }
    return 0;
}

int pwrite_full(int fd, const void *buffer, size_t length, off_t offset)
{
    const unsigned char *cursor = buffer;
    size_t written = 0;
    while (written < length) {
        ssize_t count = pwrite(fd, cursor + written, length - written, offset + (off_t)written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        written += (size_t)count;
    }
    return 0;
}

int make_password_hash(const char *password, char *hash, size_t capacity)
{
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    unsigned char random_bytes[16];
    size_t filled = 0;
    while (filled < sizeof(random_bytes)) {
        ssize_t count = getrandom(random_bytes + filled, sizeof(random_bytes) - filled, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        filled += (size_t)count;
    }
    char salt[32];
    memcpy(salt, "$6$", 3);
    for (size_t i = 0; i < sizeof(random_bytes); i++)
        salt[3 + i] = alphabet[random_bytes[i] & 63U];
    salt[3 + sizeof(random_bytes)] = '$';
    salt[4 + sizeof(random_bytes)] = '\0';
    struct crypt_data state;
    memset(&state, 0, sizeof(state));
    char *encoded = crypt_r(password, salt, &state);
    if (encoded == NULL || strlen(encoded) + 1 > capacity)
        return -1;
    memcpy(hash, encoded, strlen(encoded) + 1);
    return 0;
}

int verify_password(const char *password, const char *hash)
{
    if (password == NULL || hash == NULL || hash[0] == '\0')
        return 0;
    struct crypt_data state;
    memset(&state, 0, sizeof(state));
    char *encoded = crypt_r(password, hash, &state);
    return encoded != NULL && strcmp(encoded, hash) == 0;
}
