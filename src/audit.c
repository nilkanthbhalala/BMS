#define _GNU_SOURCE
#include "bank.h"
#include "server_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int audit_write_fd = -1;

typedef struct {
    time_t timestamp;
    pid_t process_id;
    uint32_t account_id;
    char event[24];
    char username[BANK_USER];
    char details[96];
} AuditEvent;

_Static_assert(sizeof(AuditEvent) <= PIPE_BUF, "audit event must be an atomic pipe write");

static int write_all_fd(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, cursor + written, length - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        written += (size_t)count;
    }
    return 0;
}

void audit_writer(int read_fd)
{
    int log_fd = open(BANK_AUDIT_FILE, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (log_fd < 0)
        _exit(1);
    for (;;) {
        AuditEvent event;
        unsigned char *cursor = (unsigned char *)&event;
        size_t received = 0;
        while (received < sizeof(event)) {
            ssize_t count = read(read_fd, cursor + received, sizeof(event) - received);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0) {
                close(log_fd);
                close(read_fd);
                _exit(1);
            }
            if (count == 0) {
                close(log_fd);
                close(read_fd);
                _exit(0);
            }
            received += (size_t)count;
        }
        struct tm local_time;
        char timestamp[32];
        if (localtime_r(&event.timestamp, &local_time) == NULL)
            (void)snprintf(timestamp, sizeof(timestamp), "unknown");
        else
            (void)strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local_time);
        char line[256];
        int length = snprintf(line, sizeof(line), "%s | pid=%ld | %s | account=%u | user=%s | %s\n",
                              timestamp, (long)event.process_id, event.event, event.account_id,
                              event.username, event.details);
        if (length < 0 || (size_t)length >= sizeof(line) || write_all_fd(log_fd, line, (size_t)length) < 0) {
            close(log_fd);
            close(read_fd);
            _exit(1);
        }
    }
}

void audit_log_event(const char *event, const char *username, uint32_t account_id, const char *details)
{
    if (audit_write_fd < 0)
        return;
    AuditEvent record;
    memset(&record, 0, sizeof(record));
    record.timestamp = time(NULL);
    record.process_id = getpid();
    record.account_id = account_id;
    (void)snprintf(record.event, sizeof(record.event), "%s", event);
    (void)snprintf(record.username, sizeof(record.username), "%s", username);
    (void)snprintf(record.details, sizeof(record.details), "%s", details);
    for (;;) {
        ssize_t count = write(audit_write_fd, &record, sizeof(record));
        if (count < 0 && errno == EINTR)
            continue;
        break;
    }
}

void audit_set_fd(int fd)
{
    audit_write_fd = fd;
}

void audit_stop(pid_t writer_pid)
{
    audit_log_event("SERVER_STOP", "server", 0, "graceful shutdown");
    close(audit_write_fd);
    audit_write_fd = -1;
    while (waitpid(writer_pid, NULL, 0) < 0 && errno == EINTR)
        ;
}
