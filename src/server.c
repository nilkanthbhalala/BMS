#define _GNU_SOURCE
#include "bank.h"
#include "server_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_CLIENTS 128

typedef struct {
    int socket_fd;
} ClientContext;

static volatile sig_atomic_t stopping;
static volatile sig_atomic_t signal_pipe_write = -1;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clients_finished = PTHREAD_COND_INITIALIZER;
static ClientContext *clients[MAX_CLIENTS];
static size_t active_clients;

static void *client_thread(void *argument);

static void handle_stop(int signal_number)
{
    int saved_errno = errno;
    (void)signal_number;
    stopping = 1;
    if (signal_pipe_write >= 0) {
        char byte = 1;
        ssize_t result = write((int)signal_pipe_write, &byte, sizeof(byte));
        if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            stopping = 1;
    }
    errno = saved_errno;
}

static int handle_login(int fd, char **fields, int count, Session *session)
{
    if (count != 4)
        return send_reply(fd, "ERR|Use LOGIN|role|username|password");
    int result = store_login(fields[1], fields[2], fields[3], session);
    if (result == LOGIN_OK) {
        char message[128];
        if (session->role == ROLE_ADMIN)
            (void)snprintf(message, sizeof(message), "OK|Administrator login successful");
        else if (session->role == ROLE_EMPLOYEE)
            (void)snprintf(message, sizeof(message), "OK|Bank employee login successful");
        else if (session->role == ROLE_MANAGER)
            (void)snprintf(message, sizeof(message), "OK|Manager login successful");
        else
            (void)snprintf(message, sizeof(message), "OK|Login successful. Account %u", session->account_id);
        audit_log_event("LOGIN", session->username, session->account_id,
                        session->role == ROLE_ADMIN ? "administrator" :
                        session->role == ROLE_EMPLOYEE ? "bank employee" :
                        session->role == ROLE_MANAGER ? "manager" : "account holder");
        return send_reply(fd, message);
    }
    if (result == LOGIN_INACTIVE)
        return send_reply(fd, "ERR|This account is inactive");
    if (result == LOGIN_BUSY)
        return send_reply(fd, "ERR|This login is already active");
    if (result == LOGIN_STORAGE)
        return send_reply(fd, "ERR|Could not read account files");
    return send_reply(fd, "ERR|Invalid role, username, or password");
}

void serve_client(int client_fd)
{
    Session session;
    memset(&session, 0, sizeof(session));
    char line[BANK_LINE];
    while (!stopping) {
        ssize_t length = recv_line(client_fd, line, sizeof(line));
        if (length == 0)
            break;
        if (length == -2) {
            if (send_reply(client_fd, "ERR|Request is too long") < 0)
                break;
            continue;
        }
        if (length < 0)
            break;
        char *fields[12];
        int count = split_fields(line, fields, (int)(sizeof(fields) / sizeof(fields[0])));
        if (count <= 0) {
            if (send_reply(client_fd, "ERR|Malformed request") < 0)
                break;
            continue;
        }
        if (!session.authenticated) {
            if (handle_login(client_fd, fields, count, &session) < 0)
                break;
            if (!session.authenticated)
                break;
            continue;
        }
        if (strcmp(fields[0], "LOGOUT") == 0 && count == 1) {
            (void)send_reply(client_fd, "OK|Logged out");
            break;
        }
        int result;
        if (session.role == ROLE_ADMIN)
            result = dispatch_administrator(client_fd, fields, count, &session);
        else if (session.role == ROLE_EMPLOYEE || session.role == ROLE_MANAGER)
            result = session.role == ROLE_MANAGER ?
                     dispatch_manager(client_fd, fields, count, &session) :
                     dispatch_bank_employee(client_fd, fields, count, &session);
        else
            result = dispatch_customer(client_fd, fields, count, &session);
        if (result < 0)
            break;
    }
    if (session.authenticated)
        audit_log_event("LOGOUT", session.username, session.account_id, "session ended");
    store_logout(&session);
}

static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535)
        return -1;
    *port = (uint16_t)value;
    return 0;
}

int main(int argc, char **argv)
{
    uint16_t port = BANK_PORT;
    if (argc > 2 || (argc == 2 && parse_port(argv[1], &port) < 0)) {
        (void)dprintf(STDERR_FILENO, "Usage: %s [port]\n", argv[0]);
        return 2;
    }
    int server_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    int reuse = 1;
    (void)setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(server_fd, 32) < 0) {
        perror("bind/listen");
        close(server_fd);
        return 1;
    }
    if (store_initialize() < 0) {
        (void)dprintf(STDERR_FILENO, "Could not initialize data files in ./%s\n", BANK_DATA_DIR);
        close(server_fd);
        return 1;
    }

    int signal_pipe[2];
    if (pipe2(signal_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        perror("pipe2");
        close(server_fd);
        return 1;
    }
    signal_pipe_write = signal_pipe[1];
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_stop;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    action.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &action, NULL);

    int audit_pipe[2];
    if (pipe2(audit_pipe, O_CLOEXEC) < 0) {
        perror("pipe2");
        close(signal_pipe[0]);
        close(signal_pipe[1]);
        close(server_fd);
        return 1;
    }
    pid_t audit_process = fork();
    if (audit_process < 0) {
        perror("fork");
        close(audit_pipe[0]);
        close(audit_pipe[1]);
        close(signal_pipe[0]);
        close(signal_pipe[1]);
        close(server_fd);
        return 1;
    }
    if (audit_process == 0) {
        close(server_fd);
        close(signal_pipe[0]);
        close(signal_pipe[1]);
        close(audit_pipe[1]);
        audit_writer(audit_pipe[0]);
    }
    close(audit_pipe[0]);
    audit_set_fd(audit_pipe[1]);

    (void)dprintf(STDOUT_FILENO, "Online Banking server listening on port %u\n", (unsigned)port);
    (void)dprintf(STDOUT_FILENO, "Audit writer process: %ld\n", (long)audit_process);
    (void)dprintf(STDOUT_FILENO, "Initial administrator on first run: admin / admin123\n");

    while (!stopping) {
        struct pollfd descriptors[2];
        descriptors[0].fd = server_fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = signal_pipe[0];
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;
        int ready = poll(descriptors, 2, -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (stopping || (descriptors[1].revents & POLLIN))
            break;
        if (!(descriptors[0].revents & POLLIN))
            continue;
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);
        int client_fd = accept4(server_fd, (struct sockaddr *)&peer, &peer_length, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            if (stopping)
                break;
            perror("accept");
            continue;
        }
        ClientContext *context = malloc(sizeof(*context));
        if (context == NULL) {
            close(client_fd);
            continue;
        }
        context->socket_fd = client_fd;
        size_t slot = MAX_CLIENTS;
        pthread_mutex_lock(&clients_mutex);
        if (active_clients < MAX_CLIENTS) {
            for (size_t i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == NULL) {
                    slot = i;
                    clients[i] = context;
                    active_clients++;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&clients_mutex);
        if (slot == MAX_CLIENTS) {
            close(client_fd);
            free(context);
            continue;
        }
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_thread, context) != 0) {
            pthread_mutex_lock(&clients_mutex);
            clients[slot] = NULL;
            active_clients--;
            (void)close(client_fd);
            (void)pthread_cond_broadcast(&clients_finished);
            pthread_mutex_unlock(&clients_mutex);
            free(context);
            continue;
        }
        (void)pthread_detach(thread);
        (void)dprintf(STDOUT_FILENO, "Started client thread for socket %d\n", client_fd);
    }
    close(server_fd);
    pthread_mutex_lock(&clients_mutex);
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] != NULL)
            (void)shutdown(clients[i]->socket_fd, SHUT_RDWR);
    }
    while (active_clients > 0)
        (void)pthread_cond_wait(&clients_finished, &clients_mutex);
    pthread_mutex_unlock(&clients_mutex);
    audit_stop(audit_process);
    signal_pipe_write = -1;
    close(signal_pipe[0]);
    close(signal_pipe[1]);
    return 0;
}

static void *client_thread(void *argument)
{
    ClientContext *context = argument;
    int client_fd = context->socket_fd;
    serve_client(client_fd);
    pthread_mutex_lock(&clients_mutex);
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == context) {
            clients[i] = NULL;
            break;
        }
    }
    (void)close(client_fd);
    if (active_clients > 0)
        active_clients--;
    (void)pthread_cond_broadcast(&clients_finished);
    pthread_mutex_unlock(&clients_mutex);
    free(context);
    return NULL;
}
