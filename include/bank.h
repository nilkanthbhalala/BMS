#ifndef BANK_H
#define BANK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BANK_PORT 5050
#define BANK_LINE 2048
#define BANK_NAME 64
#define BANK_USER 32
#define BANK_PHONE 32
#define BANK_HASH 128
#define BANK_TIME 32

#define BANK_DATA_DIR "data"
#define BANK_ACCOUNTS_FILE BANK_DATA_DIR "/accounts.dat"
#define BANK_ADMIN_FILE BANK_DATA_DIR "/admin.dat"
#define BANK_TRANSACTIONS_FILE BANK_DATA_DIR "/transactions.dat"
#define BANK_AUDIT_FILE BANK_DATA_DIR "/audit.log"
#define BANK_STAFF_FILE BANK_DATA_DIR "/staff.dat"
#define BANK_LOANS_FILE BANK_DATA_DIR "/loans.dat"
#define BANK_JOURNAL_FILE BANK_DATA_DIR "/journal.dat"

enum {
    ACCOUNT_NORMAL = 1,
    ACCOUNT_JOINT = 2
};

enum {
    ROLE_CUSTOMER = 1,
    ROLE_JOINT = 2,
    ROLE_EMPLOYEE = 3,
    ROLE_MANAGER = 4,
    ROLE_ADMIN = 5
};

enum {
    LOAN_PENDING = 1,
    LOAN_APPROVED = 2,
    LOAN_REJECTED = 3
};

enum {
    LOGIN_OK = 0,
    LOGIN_INVALID = 1,
    LOGIN_INACTIVE = 2,
    LOGIN_BUSY = 3,
    LOGIN_STORAGE = 4
};

enum {
    BANK_OK = 0,
    BANK_NOT_FOUND = 1,
    BANK_INACTIVE = 2,
    BANK_INSUFFICIENT = 3,
    BANK_INVALID = 4,
    BANK_BUSY = 5,
    BANK_STORAGE = 6
};

typedef struct {
    uint32_t id;
    uint32_t type;
    uint32_t active;
    uint32_t session_a;
    uint32_t session_b;
    int64_t balance_cents;
    char name_a[BANK_NAME];
    char name_b[BANK_NAME];
    char username_a[BANK_USER];
    char username_b[BANK_USER];
    char hash_a[BANK_HASH];
    char hash_b[BANK_HASH];
    char phone[BANK_PHONE];
} Account;

typedef struct {
    char username[BANK_USER];
    char password_hash[BANK_HASH];
} Admin;

typedef struct {
    uint32_t account_id;
    char actor[BANK_USER];
    char kind[16];
    int64_t amount_cents;
    int64_t before_cents;
    int64_t after_cents;
    char timestamp[BANK_TIME];
} Transaction;

typedef struct {
    uint32_t role;
    uint32_t active;
    char username[BANK_USER];
    char password_hash[BANK_HASH];
} Staff;

typedef struct {
    uint32_t id;
    uint32_t account_id;
    uint32_t status;
    uint32_t term_months;
    int64_t principal_cents;
    int64_t rate_basis_points;
    char applicant[BANK_USER];
    char reviewer[BANK_USER];
    char requested_at[BANK_TIME];
    char reviewed_at[BANK_TIME];
} Loan;

typedef struct {
    int authenticated;
    int administrator;
    int role;
    int slot;
    uint32_t account_id;
    uint32_t account_type;
    char username[BANK_USER];
} Session;

int send_all(int fd, const void *data, size_t length);
int send_line(int fd, const char *line);
ssize_t recv_line(int fd, char *buffer, size_t capacity);
int send_reply(int fd, const char *line);
int split_fields(char *line, char **fields, int capacity);
int parse_money(const char *text, int64_t *cents);
void format_money(int64_t cents, char *buffer, size_t capacity);
int parse_u32(const char *text, uint32_t *value);
int lock_range(int fd, short type, off_t start, off_t length);
int pread_full(int fd, void *buffer, size_t length, off_t offset);
int pwrite_full(int fd, const void *buffer, size_t length, off_t offset);
int make_password_hash(const char *password, char *hash, size_t capacity);
int verify_password(const char *password, const char *hash);

int store_initialize(void);
int store_login(const char *role, const char *username, const char *password, Session *session);
void store_logout(Session *session);
int store_change_password(const Session *session, const char *old_password, const char *new_password);
int store_get_account(const Session *session, Account *account);
int store_get_balance(const Session *session, int64_t *balance);
int store_deposit(const Session *session, int64_t amount, int64_t *balance);
int store_withdraw(const Session *session, int64_t amount, int64_t *balance);
int store_history(const Session *session, int socket_fd);
int store_admin_add(int socket_fd, int joint, char **fields);
int store_admin_delete(int socket_fd, uint32_t account_id);
int store_admin_modify(int socket_fd, uint32_t account_id, const char *name_a, const char *name_b, const char *phone, int active);
int store_admin_list(int socket_fd);
int store_admin_search(int socket_fd, const char *key);
int store_admin_change_password(const char *old_password, const char *new_password);
int store_apply_loan(const Session *session, int64_t amount, uint32_t term_months, uint32_t *loan_id);
int store_list_loans(int socket_fd, const Session *session, int all_accounts);
int store_review_loan(int socket_fd, const Session *session, uint32_t loan_id, int approve);
int store_admin_add_staff(int socket_fd, const char *role, const char *username, const char *password);
int store_staff_transaction(int socket_fd, const Session *session, uint32_t account_id,
                            int64_t amount, int withdraw);
int store_recover_journal(void);
void audit_log_event(const char *event, const char *username, uint32_t account_id, const char *details);

void serve_client(int client_fd);
int customer_apply_loan(int socket_fd, const Session *session, char **fields);
int customer_show_loans(int socket_fd, const Session *session);
int bank_employee_transaction(int socket_fd, const Session *session, char **fields, int withdraw);
int manager_review_loan(int socket_fd, const Session *session, char **fields);
int administrator_add_staff(int socket_fd, const Session *session, char **fields);
int dispatch_customer(int socket_fd, char **fields, int count, const Session *session);
int dispatch_bank_employee(int socket_fd, char **fields, int count, const Session *session);
int dispatch_manager(int socket_fd, char **fields, int count, const Session *session);
int dispatch_administrator(int socket_fd, char **fields, int count, const Session *session);

#endif
