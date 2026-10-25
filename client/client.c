#define _DEFAULT_SOURCE
#include "bank.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

static int write_text(const char *text)
{
    size_t length = strlen(text);
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(STDOUT_FILENO, text + done, length - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        done += (size_t)count;
    }
    return 0;
}

static int read_input(const char *prompt, char *buffer, size_t capacity, int secret)
{
    if (capacity < 2 || write_text(prompt) < 0)
        return -1;
    struct termios original;
    int changed = 0;
    if (secret && isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original) == 0) {
        struct termios hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0)
            changed = 1;
    }
    size_t used = 0;
    int overflow = 0;
    for (;;) {
        char byte;
        ssize_t count = read(STDIN_FILENO, &byte, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (changed)
                (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
            return -1;
        }
        if (byte == '\n' || byte == '\r')
            break;
        if (used + 1 < capacity)
            buffer[used++] = byte;
        else
            overflow = 1;
    }
    buffer[used] = '\0';
    if (changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        (void)write_text("\n");
    }
    return overflow ? -1 : (int)used;
}

static int send_command(int socket_fd, const char *command)
{
    size_t length = strlen(command);
    char buffer[BANK_LINE + 1];
    if (length + 1 > sizeof(buffer))
        return -1;
    memcpy(buffer, command, length);
    buffer[length] = '\n';
    size_t sent = 0;
    while (sent <= length) {
        ssize_t count = send(socket_fd, buffer + sent, length + 1 - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        sent += (size_t)count;
    }
    return 0;
}

static int receive_reply(int socket_fd, char *first_line, size_t capacity)
{
    char line[1024];
    int first = 1;
    int success = 0;
    for (;;) {
        ssize_t length = recv_line(socket_fd, line, sizeof(line));
        if (length <= 0)
            return -1;
        if (strcmp(line, ".") == 0)
            break;
        if (first) {
            if (capacity > 0) {
                size_t copy_length = strnlen(line, capacity - 1);
                memcpy(first_line, line, copy_length);
                first_line[copy_length] = '\0';
            }
            success = strncmp(line, "OK|", 3) == 0;
            first = 0;
        }
        const char *display = line;
        if (strncmp(line, "OK|", 3) == 0 || strncmp(line, "ERR|", 4) == 0)
            display = strchr(line, '|') + 1;
        if (write_text(display) < 0 || write_text("\n") < 0)
            return -1;
    }
    return success;
}

static int ask(const char *prompt, char *buffer, size_t capacity, int secret)
{
    int result = read_input(prompt, buffer, capacity, secret);
    if (result < 0) {
        (void)write_text("Input was too long or unavailable.\n");
        return -1;
    }
    if (strchr(buffer, '|') != NULL) {
        (void)write_text("The | character is not allowed.\n");
        return -1;
    }
    return 0;
}

static int exchange(int socket_fd, const char *command)
{
    char response[256];
    if (send_command(socket_fd, command) < 0)
        return -1;
    int result = receive_reply(socket_fd, response, sizeof(response));
    return result;
}

static int customer_menu(int socket_fd)
{
    char choice[32];
    char first[128];
    char second[128];
    char command[BANK_LINE];
    for (;;) {
        (void)write_text("\n1. Deposit\n2. Withdraw\n3. Balance enquiry\n4. Change password\n5. View details\n6. Transaction history\n7. Apply for loan\n8. View loan requests\n9. Logout\n");
        if (ask("Choice: ", choice, sizeof(choice), 0) < 0)
            continue;
        if (strcmp(choice, "1") == 0 || strcmp(choice, "2") == 0) {
            if (ask("Amount (example 125.50): ", first, sizeof(first), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "%s|%s", strcmp(choice, "1") == 0 ? "DEPOSIT" : "WITHDRAW", first);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "3") == 0) {
            if (exchange(socket_fd, "BALANCE") < 0)
                return -1;
        } else if (strcmp(choice, "4") == 0) {
            if (ask("Current password: ", first, sizeof(first), 1) < 0 ||
                ask("New password (at least 8 characters): ", second, sizeof(second), 1) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "CHPASS|%s|%s", first, second);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "5") == 0) {
            if (exchange(socket_fd, "DETAILS") < 0)
                return -1;
        } else if (strcmp(choice, "6") == 0) {
            if (exchange(socket_fd, "HISTORY") < 0)
                return -1;
        } else if (strcmp(choice, "7") == 0) {
            if (ask("Loan amount: ", first, sizeof(first), 0) < 0 ||
                ask("Term in months (1-360): ", second, sizeof(second), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "APPLY_LOAN|%s|%s", first, second);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "8") == 0) {
            if (exchange(socket_fd, "LOANS") < 0)
                return -1;
        } else if (strcmp(choice, "9") == 0) {
            (void)exchange(socket_fd, "LOGOUT");
            return 0;
        } else {
            (void)write_text("Choose a number from 1 to 9.\n");
        }
    }
}

static int admin_menu(int socket_fd)
{
    char choice[32], fields[8][128], command[BANK_LINE];
    for (;;) {
        (void)write_text("\n1. Add normal account\n2. Add joint account\n3. Delete account\n4. Modify account\n5. Search account\n6. List accounts\n7. Change administrator password\n8. Add employee/manager login\n9. List employee/manager logins\n10. Modify employee/manager login\n11. View loan queue\n12. Review loan\n13. Logout\n");
        if (ask("Choice: ", choice, sizeof(choice), 0) < 0)
            continue;
        if (strcmp(choice, "1") == 0) {
            if (ask("Account holder name: ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("Username: ", fields[1], sizeof(fields[1]), 0) < 0 ||
                ask("Password (at least 8 characters): ", fields[2], sizeof(fields[2]), 1) < 0 ||
                ask("Phone: ", fields[3], sizeof(fields[3]), 0) < 0 ||
                ask("Opening balance: ", fields[4], sizeof(fields[4]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "ADD_NORMAL|%s|%s|%s|%s|%s",
                           fields[0], fields[1], fields[2], fields[3], fields[4]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "2") == 0) {
            if (ask("First holder name: ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("First username: ", fields[1], sizeof(fields[1]), 0) < 0 ||
                ask("First password: ", fields[2], sizeof(fields[2]), 1) < 0 ||
                ask("Second holder name: ", fields[3], sizeof(fields[3]), 0) < 0 ||
                ask("Second username: ", fields[4], sizeof(fields[4]), 0) < 0 ||
                ask("Second password: ", fields[5], sizeof(fields[5]), 1) < 0 ||
                ask("Phone: ", fields[6], sizeof(fields[6]), 0) < 0 ||
                ask("Opening balance: ", fields[7], sizeof(fields[7]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "ADD_JOINT|%s|%s|%s|%s|%s|%s|%s|%s",
                           fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "3") == 0) {
            if (ask("Account number: ", fields[0], sizeof(fields[0]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "DELETE|%s", fields[0]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "4") == 0) {
            (void)write_text("For a normal account, leave the second holder name and username blank. Account holders must log out before usernames change. Active: 1, inactive: 0.\n");
            if (ask("Account number: ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("First holder name: ", fields[1], sizeof(fields[1]), 0) < 0 ||
                ask("Second holder name: ", fields[2], sizeof(fields[2]), 0) < 0 ||
                ask("First username: ", fields[3], sizeof(fields[3]), 0) < 0 ||
                ask("Second username: ", fields[4], sizeof(fields[4]), 0) < 0 ||
                ask("Phone: ", fields[5], sizeof(fields[5]), 0) < 0 ||
                ask("Active (1/0): ", fields[6], sizeof(fields[6]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "MODIFY|%s|%s|%s|%s|%s|%s|%s",
                           fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "5") == 0) {
            if (ask("Account number or username: ", fields[0], sizeof(fields[0]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "SEARCH|%s", fields[0]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "6") == 0) {
            if (exchange(socket_fd, "LIST") < 0)
                return -1;
        } else if (strcmp(choice, "7") == 0) {
            if (ask("Current password: ", fields[0], sizeof(fields[0]), 1) < 0 ||
                ask("New password (at least 8 characters): ", fields[1], sizeof(fields[1]), 1) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "CHPASS|%s|%s", fields[0], fields[1]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "8") == 0) {
            if (ask("Role (employee or manager): ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("Username: ", fields[1], sizeof(fields[1]), 0) < 0 ||
                ask("Password (at least 8 characters): ", fields[2], sizeof(fields[2]), 1) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "ADD_STAFF|%s|%s|%s", fields[0], fields[1], fields[2]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "9") == 0) {
            if (exchange(socket_fd, "STAFF_LIST") < 0)
                return -1;
        } else if (strcmp(choice, "10") == 0) {
            (void)write_text("Leave new username or password blank to keep it unchanged. Passwords are never displayed. Active: 1, inactive: 0, blank keeps current status.\n");
            if (ask("Current staff username: ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("New username: ", fields[1], sizeof(fields[1]), 0) < 0 ||
                ask("New password: ", fields[2], sizeof(fields[2]), 1) < 0 ||
                ask("Active (1/0): ", fields[3], sizeof(fields[3]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "STAFF_MODIFY|%s|%s|%s|%s",
                           fields[0], fields[1], fields[2], fields[3]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "11") == 0) {
            if (exchange(socket_fd, "LOANS") < 0)
                return -1;
        } else if (strcmp(choice, "12") == 0) {
            if (ask("Loan number: ", fields[0], sizeof(fields[0]), 0) < 0 ||
                ask("Decision (approve or reject): ", fields[1], sizeof(fields[1]), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "REVIEW|%s|%s", fields[0], fields[1]);
            if (exchange(socket_fd, command) < 0)
                return -1;
        } else if (strcmp(choice, "13") == 0) {
            (void)exchange(socket_fd, "LOGOUT");
            return 0;
        } else {
            (void)write_text("Choose a number from 1 to 13.\n");
        }
    }
}

static int staff_menu(int socket_fd, int manager)
{
    char choice[32], first[128], second[128], command[BANK_LINE];
    for (;;) {
        (void)write_text(manager ?
            "\n1. List accounts\n2. Search account\n3. Deposit to account\n4. Withdraw from account\n5. View loan queue\n6. Review loan\n7. List bank employee logins\n8. Modify bank employee login\n9. Change password\n10. Logout\n" :
            "\n1. List accounts\n2. Search account\n3. Deposit to account\n4. Withdraw from account\n5. View loan queue\n6. Change password\n7. Logout\n");
        if (ask("Choice: ", choice, sizeof(choice), 0) < 0)
            continue;
        if (strcmp(choice, "1") == 0) {
            if (exchange(socket_fd, "LIST") < 0) return -1;
        } else if (strcmp(choice, "2") == 0) {
            if (ask("Account number or username: ", first, sizeof(first), 0) < 0) continue;
            (void)snprintf(command, sizeof(command), "SEARCH|%s", first);
            if (exchange(socket_fd, command) < 0) return -1;
        } else if (strcmp(choice, "3") == 0 || strcmp(choice, "4") == 0) {
            if (ask("Account number: ", first, sizeof(first), 0) < 0 ||
                ask("Amount: ", second, sizeof(second), 0) < 0) continue;
            (void)snprintf(command, sizeof(command), "%s|%s|%s", strcmp(choice, "3") == 0 ? "DEPOSIT" : "WITHDRAW", first, second);
            if (exchange(socket_fd, command) < 0) return -1;
        } else if (strcmp(choice, "5") == 0) {
            if (exchange(socket_fd, "LOANS") < 0) return -1;
        } else if (manager && strcmp(choice, "6") == 0) {
            if (ask("Loan number: ", first, sizeof(first), 0) < 0 ||
                ask("Decision (approve or reject): ", second, sizeof(second), 0) < 0) continue;
            (void)snprintf(command, sizeof(command), "REVIEW|%s|%s", first, second);
            if (exchange(socket_fd, command) < 0) return -1;
        } else if (manager && strcmp(choice, "7") == 0) {
            if (exchange(socket_fd, "STAFF_LIST") < 0) return -1;
        } else if (manager && strcmp(choice, "8") == 0) {
            (void)write_text("You can modify employee logins only. Leave new username or password blank to keep it unchanged. Passwords are never displayed. Active: 1, inactive: 0, blank keeps current status.\n");
            if (ask("Current employee username: ", first, sizeof(first), 0) < 0 ||
                ask("New username: ", second, sizeof(second), 0) < 0)
                continue;
            char new_password[128], active[8];
            if (ask("New password: ", new_password, sizeof(new_password), 1) < 0 ||
                ask("Active (1/0): ", active, sizeof(active), 0) < 0)
                continue;
            (void)snprintf(command, sizeof(command), "STAFF_MODIFY|%s|%s|%s|%s",
                           first, second, new_password, active);
            if (exchange(socket_fd, command) < 0) return -1;
        } else if (strcmp(choice, manager ? "9" : "6") == 0) {
            if (ask("Current password: ", first, sizeof(first), 1) < 0 ||
                ask("New password: ", second, sizeof(second), 1) < 0) continue;
            (void)snprintf(command, sizeof(command), "CHPASS|%s|%s", first, second);
            if (exchange(socket_fd, command) < 0) return -1;
        } else if (strcmp(choice, manager ? "10" : "7") == 0) {
            (void)exchange(socket_fd, "LOGOUT");
            return 0;
        }
    }
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

static int open_connection(const char *host, uint16_t port)
{
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) != 1)
        return -1;
    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0)
        return -1;
    if (connect(socket_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

int main(int argc, char **argv)
{
    const char *host = "127.0.0.1";
    uint16_t port = BANK_PORT;
    if (argc > 3) {
        (void)write_text("Usage: client [IPv4-address] [port]\n");
        return 2;
    }
    if (argc >= 2)
        host = argv[1];
    if (argc == 3 && parse_port(argv[2], &port) < 0) {
        (void)write_text("Usage: client [IPv4-address] [port]\n");
        return 2;
    }
    char role_choice[32], username[128], password[128], command[BANK_LINE];
    for (;;) {
        (void)write_text("\nOnline Banking System\n1. Normal account\n2. Joint account\n3. Bank employee\n4. Manager\n5. Administrator\n6. Quit\n");
        if (ask("Choice: ", role_choice, sizeof(role_choice), 0) < 0)
            continue;
        if (strcmp(role_choice, "6") == 0)
            return 0;
        const char *role = strcmp(role_choice, "1") == 0 ? "user": strcmp(role_choice, "2") == 0 ? "joint": strcmp(role_choice, "3") == 0 ? "employee":
            strcmp(role_choice, "4") == 0 ? "manager": strcmp(role_choice, "5") == 0 ? "admin" : NULL;

        if (role == NULL) {
            (void)write_text("Choose a number from 1 to 6.\n");
            continue;
        }
        int socket_fd = open_connection(host, port);
        if (socket_fd < 0) {
            (void)write_text("Could not connect. Check the server address and port.\n");
            return 1;
        }
        if (ask("Username: ", username, sizeof(username), 0) < 0 ||
            ask("Password: ", password, sizeof(password), 1) < 0) {
            close(socket_fd);
            continue;
        }
        (void)snprintf(command, sizeof(command), "LOGIN|%s|%s|%s", role, username, password);
        if (send_command(socket_fd, command) < 0) {
            close(socket_fd);
            return 1;
        }
        char response[256];
        int login_ok = receive_reply(socket_fd, response, sizeof(response));
        if (login_ok < 0) {
            (void)write_text("Server disconnected.\n");
            close(socket_fd);
            return 1;
        }
        if (login_ok)
            (void)write_text("\n");
        int menu_result = 0;
        if (login_ok) {
            if (strcmp(role, "admin") == 0) menu_result = admin_menu(socket_fd);
            else if (strcmp(role, "employee") == 0) menu_result = staff_menu(socket_fd, 0);
            else if (strcmp(role, "manager") == 0) menu_result = staff_menu(socket_fd, 1);
            else menu_result = customer_menu(socket_fd);
        }
        close(socket_fd);
        if (menu_result < 0) {
            (void)write_text("Connection closed.\n");
            return 1;
        }
    }
}
