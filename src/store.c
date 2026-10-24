#define _GNU_SOURCE
#include "bank.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint32_t magic;
    uint32_t has_transaction;
    uint32_t has_loan;
    uint32_t reserved;
    off_t account_offset;
    off_t transaction_offset;
    off_t loan_offset;
    Account account;
    Transaction transaction;
    Loan loan;
    uint64_t checksum;
} JournalRecord;

#define JOURNAL_MAGIC 0x42414e4bU

static pthread_mutex_t loan_review_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t journal_checksum(const JournalRecord *record)
{
    const unsigned char *bytes = (const unsigned char *)record;
    uint64_t value = UINT64_C(1469598103934665603);
    size_t length = offsetof(JournalRecord, checksum);
    for (size_t i = 0; i < length; i++) {
        value ^= bytes[i];
        value *= UINT64_C(1099511628211);
    }
    return value;
}

int store_recover_journal(void)
{
    int journal_fd = open(BANK_JOURNAL_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (journal_fd < 0)
        return -1;
    struct stat status;
    int result = -1;
    if (fstat(journal_fd, &status) < 0)
        goto done;
    if (status.st_size == 0) {
        result = 0;
        goto done;
    }
    if (status.st_size != (off_t)sizeof(JournalRecord)) {
        if (ftruncate(journal_fd, 0) == 0 && fsync(journal_fd) == 0)
            result = 0;
        goto done;
    }
    JournalRecord record;
    if (pread_full(journal_fd, &record, sizeof(record), 0) != 0 ||
        record.magic != JOURNAL_MAGIC || record.checksum != journal_checksum(&record)) {
        if (ftruncate(journal_fd, 0) == 0 && fsync(journal_fd) == 0)
            result = 0;
        goto done;
    }
    int account_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    int transaction_fd = open(BANK_TRANSACTIONS_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    int loan_fd = record.has_loan ? open(BANK_LOANS_FILE, O_RDWR | O_CLOEXEC) : -1;
    if (account_fd < 0 || transaction_fd < 0 || (record.has_loan && loan_fd < 0)) {
        if (account_fd >= 0) close(account_fd);
        if (transaction_fd >= 0) close(transaction_fd);
        if (loan_fd >= 0) close(loan_fd);
        goto done;
    }
    int ok = pwrite_full(account_fd, &record.account, sizeof(record.account), record.account_offset) == 0 &&
             fsync(account_fd) == 0;
    if (ok && record.has_transaction)
        ok = pwrite_full(transaction_fd, &record.transaction, sizeof(record.transaction),
                         record.transaction_offset) == 0 && fsync(transaction_fd) == 0;
    if (ok && record.has_loan)
        ok = pwrite_full(loan_fd, &record.loan, sizeof(record.loan), record.loan_offset) == 0 &&
             fsync(loan_fd) == 0;
    close(account_fd);
    close(transaction_fd);
    if (loan_fd >= 0) close(loan_fd);
    if (ok && ftruncate(journal_fd, 0) == 0 && fsync(journal_fd) == 0)
        result = 0;
done:
    close(journal_fd);
    return result;
}

static int commit_financial(Account *account, off_t account_offset,
                            Transaction *transaction, Loan *loan, off_t loan_offset)
{
    int intent_durable = 0;
    int journal_fd = open(BANK_JOURNAL_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    int account_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    int transaction_fd = open(BANK_TRANSACTIONS_FILE, O_RDWR | O_CLOEXEC);
    int loan_fd = loan == NULL ? -1 : open(BANK_LOANS_FILE, O_RDWR | O_CLOEXEC);
    if (journal_fd < 0 || account_fd < 0 || transaction_fd < 0 || (loan != NULL && loan_fd < 0))
        goto failed;
    if (lock_range(journal_fd, F_WRLCK, 0, 0) < 0 ||
        lock_range(transaction_fd, F_WRLCK, 0, 0) < 0 ||
        (loan != NULL && lock_range(loan_fd, F_WRLCK, 0, 0) < 0))
        goto unlock;
    struct stat tx_status;
    if (fstat(transaction_fd, &tx_status) < 0 ||
        tx_status.st_size % (off_t)sizeof(Transaction) != 0)
        goto unlock;
    JournalRecord record;
    memset(&record, 0, sizeof(record));
    record.magic = JOURNAL_MAGIC;
    record.account_offset = account_offset;
    record.account = *account;
    if (transaction != NULL) {
        record.has_transaction = 1;
        record.transaction_offset = tx_status.st_size;
        record.transaction = *transaction;
    }
    if (loan != NULL) {
        record.has_loan = 1;
        record.loan_offset = loan_offset;
        record.loan = *loan;
    }
    record.checksum = journal_checksum(&record);
    if (ftruncate(journal_fd, 0) < 0 || pwrite_full(journal_fd, &record, sizeof(record), 0) < 0 ||
        fsync(journal_fd) < 0)
        goto unlock;
    intent_durable = 1;
    if (pwrite_full(account_fd, account, sizeof(*account), account_offset) < 0 || fsync(account_fd) < 0)
        goto unlock;
    if (transaction != NULL &&
        (pwrite_full(transaction_fd, transaction, sizeof(*transaction), record.transaction_offset) < 0 ||
         fsync(transaction_fd) < 0))
        goto unlock;
    if (loan != NULL && (pwrite_full(loan_fd, loan, sizeof(*loan), loan_offset) < 0 || fsync(loan_fd) < 0))
        goto unlock;
    if (ftruncate(journal_fd, 0) < 0 || fsync(journal_fd) < 0)
        goto unlock;
    (void)lock_range(transaction_fd, F_UNLCK, 0, 0);
    if (loan != NULL) (void)lock_range(loan_fd, F_UNLCK, 0, 0);
    (void)lock_range(journal_fd, F_UNLCK, 0, 0);
    close(journal_fd); close(account_fd); close(transaction_fd);
    if (loan_fd >= 0) close(loan_fd);
    return 0;
unlock:
    (void)lock_range(transaction_fd, F_UNLCK, 0, 0);
    if (loan_fd >= 0) (void)lock_range(loan_fd, F_UNLCK, 0, 0);
    (void)lock_range(journal_fd, F_UNLCK, 0, 0);
failed:
    if (journal_fd >= 0) close(journal_fd);
    if (account_fd >= 0) close(account_fd);
    if (transaction_fd >= 0) close(transaction_fd);
    if (loan_fd >= 0) close(loan_fd);
    return intent_durable && store_recover_journal() == 0 ? 0 : -1;
}

static int text_valid(const char *text, size_t maximum, int required)
{
    if (text == NULL)
        return 0;
    size_t length = strlen(text);
    if ((required && length == 0) || length >= maximum)
        return 0;
    for (size_t i = 0; i < length; i++) {
        if (text[i] == '|' || text[i] == '\n' || text[i] == '\r')
            return 0;
    }
    return 1;
}

static int username_valid(const char *username)
{
    size_t length = strlen(username);
    if (length < 3 || length >= BANK_USER)
        return 0;
    for (size_t i = 0; i < length; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int password_valid(const char *password)
{
    size_t length = strlen(password);
    if (length < 8 || length >= 96)
        return 0;
    return text_valid(password, 96, 1);
}

static void set_timestamp(char *buffer, size_t capacity)
{
    time_t now = time(NULL);
    struct tm value;
    if (localtime_r(&now, &value) == NULL) {
        (void)snprintf(buffer, capacity, "unknown");
        return;
    }
    (void)strftime(buffer, capacity, "%Y-%m-%d %H:%M:%S", &value);
}

static int find_account(int fd, uint32_t account_id, Account *account, off_t *offset)
{
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0)
        return -1;
    for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
        if (lock_range(fd, F_RDLCK, at, (off_t)sizeof(Account)) < 0)
            return -1;
        Account current;
        int read_result = pread_full(fd, &current, sizeof(current), at);
        (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
        if (read_result != 0)
            return -1;
        if (current.id == account_id) {
            if (account != NULL)
                *account = current;
            if (offset != NULL)
                *offset = at;
            return 0;
        }
    }
    return 1;
}

static int write_reply(int fd, const char *message)
{
    return send_reply(fd, message);
}

static const char *type_name(uint32_t type)
{
    return type == ACCOUNT_JOINT ? "joint" : "normal";
}

static void account_line(const Account *account, char *buffer, size_t capacity)
{
    char money[64];
    format_money(account->balance_cents, money, sizeof(money));
    if (account->type == ACCOUNT_JOINT) {
        (void)snprintf(buffer, capacity,
                       "Account %u | %s | %s | Balance %s | %s (%s) and %s (%s) | Phone %s",
                       account->id, type_name(account->type), account->active ? "active" : "inactive",
                       money, account->name_a, account->username_a, account->name_b,
                       account->username_b, account->phone[0] ? account->phone : "-");
    } else {
        (void)snprintf(buffer, capacity,
                       "Account %u | %s | %s | Balance %s | %s (%s) | Phone %s",
                       account->id, type_name(account->type), account->active ? "active" : "inactive",
                       money, account->name_a, account->username_a,
                       account->phone[0] ? account->phone : "-");
    }
}

static int trim_partial_file(const char *path, size_t record_size)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat status;
    int result = -1;
    if (fstat(fd, &status) == 0) {
        off_t remainder = status.st_size % (off_t)record_size;
        result = remainder == 0 || (ftruncate(fd, status.st_size - remainder) == 0 && fsync(fd) == 0) ? 0 : -1;
    }
    close(fd);
    return result;
}

int store_initialize(void)
{
    if (mkdir(BANK_DATA_DIR, 0700) < 0 && errno != EEXIST)
        return -1;
    const char *initial_files[] = { BANK_ACCOUNTS_FILE, BANK_TRANSACTIONS_FILE, BANK_LOANS_FILE, BANK_JOURNAL_FILE };
    for (size_t i = 0; i < sizeof(initial_files) / sizeof(initial_files[0]); i++) {
        int fd = open(initial_files[i], O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0)
            return -1;
        close(fd);
    }
    int directory_fd = open(BANK_DATA_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || fsync(directory_fd) < 0) {
        if (directory_fd >= 0) close(directory_fd);
        return -1;
    }
    close(directory_fd);
    if (store_recover_journal() < 0)
        return -1;
    if (trim_partial_file(BANK_ACCOUNTS_FILE, sizeof(Account)) < 0 ||
        trim_partial_file(BANK_TRANSACTIONS_FILE, sizeof(Transaction)) < 0 ||
        trim_partial_file(BANK_LOANS_FILE, sizeof(Loan)) < 0)
        return -1;
    int accounts_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (accounts_fd < 0)
        return -1;
    if (lock_range(accounts_fd, F_WRLCK, 0, 0) < 0) {
        close(accounts_fd);
        return -1;
    }
    struct stat accounts_status;
    int valid = fstat(accounts_fd, &accounts_status) == 0 &&
                accounts_status.st_size % (off_t)sizeof(Account) == 0;
    if (valid) {
        for (off_t at = 0; at < accounts_status.st_size; at += (off_t)sizeof(Account)) {
            Account account;
            if (pread_full(accounts_fd, &account, sizeof(account), at) != 0) {
                valid = 0;
                break;
            }
            if (account.session_a || account.session_b) {
                account.session_a = 0;
                account.session_b = 0;
                if (pwrite_full(accounts_fd, &account, sizeof(account), at) < 0) {
                    valid = 0;
                    break;
                }
            }
        }
    }
    (void)lock_range(accounts_fd, F_UNLCK, 0, 0);
    close(accounts_fd);
    if (!valid)
        return -1;

    int loans_fd = open(BANK_LOANS_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    int journal_fd = open(BANK_JOURNAL_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (loans_fd < 0 || journal_fd < 0) {
        if (loans_fd >= 0) close(loans_fd);
        if (journal_fd >= 0) close(journal_fd);
        return -1;
    }
    struct stat loans_status;
    valid = fstat(loans_fd, &loans_status) == 0 && loans_status.st_size % (off_t)sizeof(Loan) == 0;
    close(loans_fd);
    close(journal_fd);
    if (!valid || store_recover_journal() < 0)
        return -1;
    accounts_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (accounts_fd < 0 || lock_range(accounts_fd, F_WRLCK, 0, 0) < 0) {
        if (accounts_fd >= 0) close(accounts_fd);
        return -1;
    }
    if (fstat(accounts_fd, &accounts_status) < 0 || accounts_status.st_size % (off_t)sizeof(Account) != 0) {
        (void)lock_range(accounts_fd, F_UNLCK, 0, 0);
        close(accounts_fd);
        return -1;
    }
    for (off_t at = 0; at < accounts_status.st_size; at += (off_t)sizeof(Account)) {
        Account account;
        if (pread_full(accounts_fd, &account, sizeof(account), at) != 0) {
            valid = 0;
            break;
        }
        if (account.session_a || account.session_b) {
            account.session_a = 0;
            account.session_b = 0;
            if (pwrite_full(accounts_fd, &account, sizeof(account), at) < 0) {
                valid = 0;
                break;
            }
        }
    }
    if (valid && fsync(accounts_fd) < 0)
        valid = 0;
    (void)lock_range(accounts_fd, F_UNLCK, 0, 0);
    close(accounts_fd);
    if (!valid)
        return -1;

    int admin_fd = open(BANK_ADMIN_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (admin_fd < 0)
        return -1;
    if (lock_range(admin_fd, F_WRLCK, 0, 0) < 0) {
        close(admin_fd);
        return -1;
    }
    struct stat admin_status;
    int result = -1;
    if (fstat(admin_fd, &admin_status) == 0) {
        if (admin_status.st_size == 0) {
            Admin admin;
            memset(&admin, 0, sizeof(admin));
            (void)snprintf(admin.username, sizeof(admin.username), "admin");
            if (make_password_hash("admin123", admin.password_hash, sizeof(admin.password_hash)) == 0 &&
                pwrite_full(admin_fd, &admin, sizeof(admin), 0) == 0 && fsync(admin_fd) == 0)
                result = 0;
        } else if (admin_status.st_size == (off_t)sizeof(Admin)) {
            result = 0;
        }
    }
    (void)lock_range(admin_fd, F_UNLCK, 0, 0);
    close(admin_fd);
    if (result < 0)
        return -1;

    int staff_fd = open(BANK_STAFF_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (staff_fd < 0)
        return -1;
    if (trim_partial_file(BANK_STAFF_FILE, sizeof(Staff)) < 0) {
        close(staff_fd);
        return -1;
    }
    if (lock_range(staff_fd, F_WRLCK, 0, 0) < 0) {
        close(staff_fd);
        return -1;
    }
    struct stat staff_status;
    result = -1;
    if (fstat(staff_fd, &staff_status) == 0 && staff_status.st_size % (off_t)sizeof(Staff) == 0) {
        const int roles[] = { ROLE_EMPLOYEE, ROLE_MANAGER };
        const char *users[] = { "employee", "manager" };
        const char *passwords[] = { "employee123", "manager123" };
        int changed = 0;
        result = 0;
        for (size_t i = 0; i < 2; i++) {
            int exists = 0;
            for (off_t offset = 0; offset < staff_status.st_size; offset += (off_t)sizeof(Staff)) {
                Staff current;
                if (pread_full(staff_fd, &current, sizeof(current), offset) != 0) {
                    result = -1;
                    break;
                }
                if (current.role == (uint32_t)roles[i] && strcmp(current.username, users[i]) == 0) {
                    exists = 1;
                    break;
                }
            }
            if (result < 0 || exists)
                continue;
            Staff staff;
            memset(&staff, 0, sizeof(staff));
            staff.role = (uint32_t)roles[i];
            staff.active = 1;
            (void)snprintf(staff.username, sizeof(staff.username), "%s", users[i]);
            if (make_password_hash(passwords[i], staff.password_hash, sizeof(staff.password_hash)) < 0 ||
                pwrite_full(staff_fd, &staff, sizeof(staff), staff_status.st_size) < 0) {
                result = -1;
                break;
            }
            staff_status.st_size += (off_t)sizeof(Staff);
            changed = 1;
        }
        if (result == 0 && changed && fsync(staff_fd) < 0)
            result = -1;
    }
    (void)lock_range(staff_fd, F_UNLCK, 0, 0);
    close(staff_fd);
    if (result < 0)
        return -1;

    int transactions_fd = open(BANK_TRANSACTIONS_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (transactions_fd < 0)
        return -1;
    struct stat transaction_status;
    int transactions_valid = fstat(transactions_fd, &transaction_status) == 0 &&
                             transaction_status.st_size % (off_t)sizeof(Transaction) == 0;
    close(transactions_fd);
    if (!transactions_valid)
        return -1;
    directory_fd = open(BANK_DATA_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;
    int directory_sync = fsync(directory_fd);
    close(directory_fd);
    return directory_sync == 0 ? 0 : -1;
}

int store_login(const char *role, const char *username, const char *password, Session *session)
{
    memset(session, 0, sizeof(*session));
    if (strcmp(role, "admin") == 0) {
        int fd = open(BANK_ADMIN_FILE, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return LOGIN_STORAGE;
        int status = LOGIN_INVALID;
        if (lock_range(fd, F_RDLCK, 0, (off_t)sizeof(Admin)) == 0) {
            Admin admin;
            if (pread_full(fd, &admin, sizeof(admin), 0) == 0) {
                if (strcmp(username, admin.username) == 0 && verify_password(password, admin.password_hash)) {
                    status = LOGIN_OK;
                    session->authenticated = 1;
                    session->administrator = 1;
                    session->role = ROLE_ADMIN;
                    (void)snprintf(session->username, sizeof(session->username), "%s", username);
                }
            } else {
                status = LOGIN_STORAGE;
            }
            (void)lock_range(fd, F_UNLCK, 0, (off_t)sizeof(Admin));
        } else {
            status = LOGIN_STORAGE;
        }
        close(fd);
        return status;
    }
    if (strcmp(role, "employee") == 0 || strcmp(role, "manager") == 0) {
        uint32_t required_role = strcmp(role, "employee") == 0 ? ROLE_EMPLOYEE : ROLE_MANAGER;
        int fd = open(BANK_STAFF_FILE, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return LOGIN_STORAGE;
        struct stat status;
        int result = LOGIN_INVALID;
        if (fstat(fd, &status) == 0 && status.st_size % (off_t)sizeof(Staff) == 0) {
            for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Staff)) {
                if (lock_range(fd, F_RDLCK, at, (off_t)sizeof(Staff)) < 0) {
                    result = LOGIN_STORAGE;
                    break;
                }
                Staff staff;
                int read_result = pread_full(fd, &staff, sizeof(staff), at);
                (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Staff));
                if (read_result != 0) {
                    result = LOGIN_STORAGE;
                    break;
                }
                if (staff.role == required_role && staff.active && strcmp(username, staff.username) == 0 &&
                    verify_password(password, staff.password_hash)) {
                    session->authenticated = 1;
                    session->role = (int)required_role;
                    (void)snprintf(session->username, sizeof(session->username), "%s", username);
                    result = LOGIN_OK;
                    break;
                }
            }
        } else {
            result = LOGIN_STORAGE;
        }
        close(fd);
        return result;
    }
    uint32_t desired_type = strcmp(role, "user") == 0 ? ACCOUNT_NORMAL :
                            strcmp(role, "joint") == 0 ? ACCOUNT_JOINT : 0;
    if (desired_type == 0)
        return LOGIN_INVALID;
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return LOGIN_STORAGE;
    struct stat file_status;
    if (fstat(fd, &file_status) < 0 || file_status.st_size % (off_t)sizeof(Account) != 0) {
        close(fd);
        return LOGIN_STORAGE;
    }
    int result = LOGIN_INVALID;
    for (off_t at = 0; at < file_status.st_size; at += (off_t)sizeof(Account)) {
        if (lock_range(fd, F_WRLCK, at, (off_t)sizeof(Account)) < 0) {
            result = LOGIN_STORAGE;
            break;
        }
        Account account;
        if (pread_full(fd, &account, sizeof(account), at) != 0) {
            (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
            result = LOGIN_STORAGE;
            break;
        }
        int slot = -1;
        const char *hash = NULL;
        if (account.type == desired_type && strcmp(username, account.username_a) == 0) {
            slot = 0;
            hash = account.hash_a;
        } else if (account.type == ACCOUNT_JOINT && desired_type == ACCOUNT_JOINT &&
                   strcmp(username, account.username_b) == 0) {
            slot = 1;
            hash = account.hash_b;
        }
        if (slot < 0 || !verify_password(password, hash)) {
            (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
            continue;
        }
        if (!account.active) {
            result = LOGIN_INACTIVE;
        } else if ((slot == 0 && account.session_a) || (slot == 1 && account.session_b)) {
            result = LOGIN_BUSY;
        } else {
            if (slot == 0)
                account.session_a = 1;
            else
                account.session_b = 1;
            if (pwrite_full(fd, &account, sizeof(account), at) < 0) {
                result = LOGIN_STORAGE;
            } else {
                result = LOGIN_OK;
                session->authenticated = 1;
                session->account_id = account.id;
                session->account_type = account.type;
                session->slot = slot;
                session->role = account.type == ACCOUNT_JOINT ? ROLE_JOINT : ROLE_CUSTOMER;
                (void)snprintf(session->username, sizeof(session->username), "%s", username);
            }
        }
        (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
        break;
    }
    close(fd);
    return result;
}

void store_logout(Session *session)
{
    if (session == NULL || !session->authenticated)
        return;
    if (session->role == ROLE_CUSTOMER || session->role == ROLE_JOINT) {
        int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            off_t at = 0;
            if (find_account(fd, session->account_id, NULL, &at) == 0 &&
                lock_range(fd, F_WRLCK, at, (off_t)sizeof(Account)) == 0) {
                Account account;
                if (pread_full(fd, &account, sizeof(account), at) == 0 && account.id == session->account_id) {
                    if (session->slot == 0)
                        account.session_a = 0;
                    else
                        account.session_b = 0;
                    (void)pwrite_full(fd, &account, sizeof(account), at);
                }
                (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
            }
            close(fd);
        }
    }
    memset(session, 0, sizeof(*session));
}

int store_get_account(const Session *session, Account *account)
{
    if (session == NULL || !session->authenticated || session->administrator)
        return BANK_INVALID;
    int fd = open(BANK_ACCOUNTS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return BANK_STORAGE;
    int found = find_account(fd, session->account_id, account, NULL);
    close(fd);
    if (found < 0)
        return BANK_STORAGE;
    if (found > 0)
        return BANK_NOT_FOUND;
    return account->active ? BANK_OK : BANK_INACTIVE;
}

int store_get_balance(const Session *session, int64_t *balance)
{
    Account account;
    int result = store_get_account(session, &account);
    if (result == BANK_OK)
        *balance = account.balance_cents;
    return result;
}

static int change_balance(const Session *session, int64_t amount, int withdraw, int64_t *balance)
{
    if (session == NULL || !session->authenticated || session->administrator || amount <= 0)
        return BANK_INVALID;
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return BANK_STORAGE;
    off_t at = 0;
    int found = find_account(fd, session->account_id, NULL, &at);
    if (found != 0) {
        close(fd);
        return found < 0 ? BANK_STORAGE : BANK_NOT_FOUND;
    }
    if (lock_range(fd, F_WRLCK, at, (off_t)sizeof(Account)) < 0) {
        close(fd);
        return BANK_STORAGE;
    }
    Account account;
    int result = BANK_STORAGE;
    if (pread_full(fd, &account, sizeof(account), at) == 0 && account.id == session->account_id) {
        if (!account.active) {
            result = BANK_INACTIVE;
        } else if (withdraw && account.balance_cents < amount) {
            result = BANK_INSUFFICIENT;
        } else if (!withdraw && account.balance_cents > INT64_MAX - amount) {
            result = BANK_INVALID;
        } else {
            int64_t before = account.balance_cents;
            int64_t after = withdraw ? before - amount : before + amount;
            account.balance_cents = after;
            Transaction transaction;
            memset(&transaction, 0, sizeof(transaction));
            transaction.account_id = account.id;
            transaction.amount_cents = amount;
            transaction.before_cents = before;
            transaction.after_cents = after;
            (void)snprintf(transaction.actor, sizeof(transaction.actor), "%s", session->username);
            (void)snprintf(transaction.kind, sizeof(transaction.kind), "%s", withdraw ? "withdraw" : "deposit");
            set_timestamp(transaction.timestamp, sizeof(transaction.timestamp));
            if (commit_financial(&account, at, &transaction, NULL, 0) < 0) {
                result = BANK_STORAGE;
            } else {
                char detail[64];
                format_money(amount, detail, sizeof(detail));
                audit_log_event(withdraw ? "withdraw" : "deposit", session->username, account.id, detail);
                *balance = after;
                result = BANK_OK;
            }
        }
    }
    (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
    close(fd);
    return result;
}

int store_deposit(const Session *session, int64_t amount, int64_t *balance)
{
    return change_balance(session, amount, 0, balance);
}

int store_withdraw(const Session *session, int64_t amount, int64_t *balance)
{
    return change_balance(session, amount, 1, balance);
}

int store_change_password(const Session *session, const char *old_password, const char *new_password)
{
    if (session == NULL || !session->authenticated || !password_valid(new_password))
        return BANK_INVALID;
    if (session->role == ROLE_ADMIN)
        return store_admin_change_password(old_password, new_password) == 0 ? BANK_OK : BANK_INVALID;
    if (session->role == ROLE_EMPLOYEE || session->role == ROLE_MANAGER) {
        int staff_fd = open(BANK_STAFF_FILE, O_RDWR | O_CLOEXEC);
        if (staff_fd < 0)
            return BANK_STORAGE;
        struct stat staff_status;
        int staff_result = BANK_NOT_FOUND;
        if (fstat(staff_fd, &staff_status) == 0 && staff_status.st_size % (off_t)sizeof(Staff) == 0) {
            for (off_t offset = 0; offset < staff_status.st_size; offset += (off_t)sizeof(Staff)) {
                if (lock_range(staff_fd, F_WRLCK, offset, (off_t)sizeof(Staff)) < 0) {
                    staff_result = BANK_STORAGE;
                    break;
                }
                Staff staff;
                if (pread_full(staff_fd, &staff, sizeof(staff), offset) != 0) {
                    staff_result = BANK_STORAGE;
                } else if (staff.role == (uint32_t)session->role && strcmp(staff.username, session->username) == 0) {
                    if (!verify_password(old_password, staff.password_hash) ||
                        make_password_hash(new_password, staff.password_hash, sizeof(staff.password_hash)) < 0)
                        staff_result = BANK_INVALID;
                    else
                        staff_result = pwrite_full(staff_fd, &staff, sizeof(staff), offset) == 0 &&
                                       fsync(staff_fd) == 0 ? BANK_OK : BANK_STORAGE;
                    (void)lock_range(staff_fd, F_UNLCK, offset, (off_t)sizeof(Staff));
                    break;
                }
                (void)lock_range(staff_fd, F_UNLCK, offset, (off_t)sizeof(Staff));
            }
        } else {
            staff_result = BANK_STORAGE;
        }
        close(staff_fd);
        return staff_result;
    }
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return BANK_STORAGE;
    off_t at = 0;
    int found = find_account(fd, session->account_id, NULL, &at);
    if (found != 0) {
        close(fd);
        return found < 0 ? BANK_STORAGE : BANK_NOT_FOUND;
    }
    if (lock_range(fd, F_WRLCK, at, (off_t)sizeof(Account)) < 0) {
        close(fd);
        return BANK_STORAGE;
    }
    Account account;
    int result = BANK_STORAGE;
    if (pread_full(fd, &account, sizeof(account), at) == 0 && account.id == session->account_id) {
        char *hash = session->slot == 0 ? account.hash_a : account.hash_b;
        if (!verify_password(old_password, hash)) {
            result = BANK_INVALID;
        } else if (make_password_hash(new_password, hash, BANK_HASH) < 0) {
            result = BANK_STORAGE;
        } else {
            result = pwrite_full(fd, &account, sizeof(account), at) == 0 ? BANK_OK : BANK_STORAGE;
            if (result == BANK_OK)
                audit_log_event("PASSWORD_CHANGE", session->username, account.id, "account password updated");
        }
    }
    (void)lock_range(fd, F_UNLCK, at, (off_t)sizeof(Account));
    close(fd);
    return result;
}

int store_admin_change_password(const char *old_password, const char *new_password)
{
    if (!password_valid(new_password))
        return -1;
    int fd = open(BANK_ADMIN_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int result = -1;
    if (lock_range(fd, F_WRLCK, 0, (off_t)sizeof(Admin)) == 0) {
        Admin admin;
        if (pread_full(fd, &admin, sizeof(admin), 0) == 0 && verify_password(old_password, admin.password_hash) &&
            make_password_hash(new_password, admin.password_hash, sizeof(admin.password_hash)) == 0) {
            result = pwrite_full(fd, &admin, sizeof(admin), 0);
            if (result == 0)
                audit_log_event("PASSWORD_CHANGE", admin.username, 0, "administrator password updated");
        }
        (void)lock_range(fd, F_UNLCK, 0, (off_t)sizeof(Admin));
    }
    close(fd);
    return result;
}

int store_history(const Session *session, int socket_fd)
{
    int fd = open(BANK_TRANSACTIONS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Transaction file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Transaction) != 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Transaction file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock transaction file");
    }
    if (send_line(socket_fd, "OK|Transaction history") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    int rows = 0;
    for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Transaction)) {
        Transaction row;
        if (pread_full(fd, &row, sizeof(row), at) != 0) {
            (void)lock_range(fd, F_UNLCK, 0, 0);
            close(fd);
            return -1;
        }
        if (row.account_id == session->account_id) {
            char amount[64], before[64], after[64], line[512];
            format_money(row.amount_cents, amount, sizeof(amount));
            format_money(row.before_cents, before, sizeof(before));
            format_money(row.after_cents, after, sizeof(after));
            (void)snprintf(line, sizeof(line), "%s | %s | %s | %s to %s | by %s",
                           row.timestamp, row.kind, amount, before, after, row.actor);
            if (send_line(socket_fd, line) < 0) {
                (void)lock_range(fd, F_UNLCK, 0, 0);
                close(fd);
                return -1;
            }
            rows++;
        }
    }
    if (rows == 0 && send_line(socket_fd, "No transactions yet") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return send_line(socket_fd, ".");
}

static int usernames_available(int fd, const char *first, const char *second)
{
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0)
        return -1;
    for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
        Account account;
        if (pread_full(fd, &account, sizeof(account), at) != 0)
            return -1;
        if (strcmp(first, account.username_a) == 0 || strcmp(first, account.username_b) == 0 ||
            (second[0] && (strcmp(second, account.username_a) == 0 || strcmp(second, account.username_b) == 0)))
            return 0;
    }
    return 1;
}

int store_admin_add(int socket_fd, int joint, char **fields)
{
    const char *name_a = fields[1];
    const char *username_a = fields[2];
    const char *password_a = fields[3];
    const char *name_b = joint ? fields[4] : "";
    const char *username_b = joint ? fields[5] : "";
    const char *password_b = joint ? fields[6] : "";
    const char *phone = joint ? fields[7] : fields[4];
    const char *money_text = joint ? fields[8] : fields[5];
    int64_t opening_balance;
    if (!text_valid(name_a, BANK_NAME, 1) || !username_valid(username_a) || !password_valid(password_a) ||
        !text_valid(phone, BANK_PHONE, 0) || parse_money(money_text, &opening_balance) < 0)
        return write_reply(socket_fd, "ERR|Invalid account fields; passwords need at least 8 characters");
    if (joint && (!text_valid(name_b, BANK_NAME, 1) || !username_valid(username_b) ||
                  !password_valid(password_b) || strcmp(username_a, username_b) == 0))
        return write_reply(socket_fd, "ERR|Joint accounts need two distinct valid users and passwords");

    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result = -1;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = write_reply(socket_fd, "ERR|Account file is damaged");
    } else {
        int available = usernames_available(fd, username_a, joint ? username_b : "");
        if (available <= 0) {
            result = write_reply(socket_fd, available == 0 ? "ERR|A username is already in use" : "ERR|Account file read failed");
        } else {
            uint32_t next_id = 1;
            for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
                Account existing;
                if (pread_full(fd, &existing, sizeof(existing), at) != 0) {
                    next_id = 0;
                    break;
                }
                if (existing.id >= next_id) {
                    if (existing.id == UINT32_MAX) {
                        next_id = 0;
                        break;
                    }
                    next_id = existing.id + 1;
                }
            }
            if (next_id == 0) {
                result = write_reply(socket_fd, "ERR|Account number space is exhausted");
            } else {
                Account account;
                memset(&account, 0, sizeof(account));
                account.id = next_id;
                account.type = joint ? ACCOUNT_JOINT : ACCOUNT_NORMAL;
                account.active = 1;
                account.balance_cents = opening_balance;
                (void)snprintf(account.name_a, sizeof(account.name_a), "%s", name_a);
                (void)snprintf(account.username_a, sizeof(account.username_a), "%s", username_a);
                (void)snprintf(account.phone, sizeof(account.phone), "%s", phone);
                if (joint) {
                    (void)snprintf(account.name_b, sizeof(account.name_b), "%s", name_b);
                    (void)snprintf(account.username_b, sizeof(account.username_b), "%s", username_b);
                }
                int hashed = make_password_hash(password_a, account.hash_a, sizeof(account.hash_a)) == 0;
                if (joint)
                    hashed = hashed && make_password_hash(password_b, account.hash_b, sizeof(account.hash_b)) == 0;
                if (!hashed) {
                    result = write_reply(socket_fd, "ERR|Could not create account");
                } else {
                    Transaction opening;
                    memset(&opening, 0, sizeof(opening));
                    opening.account_id = account.id;
                    opening.amount_cents = opening_balance;
                    opening.before_cents = 0;
                    opening.after_cents = opening_balance;
                    (void)snprintf(opening.actor, sizeof(opening.actor), "admin");
                    (void)snprintf(opening.kind, sizeof(opening.kind), "opening");
                    set_timestamp(opening.timestamp, sizeof(opening.timestamp));
                    if (commit_financial(&account, status.st_size, &opening, NULL, 0) < 0) {
                        result = write_reply(socket_fd, "ERR|Could not create account");
                    } else {
                        char line[128];
                        (void)snprintf(line, sizeof(line), "OK|Created account %u", account.id);
                        audit_log_event("ACCOUNT_ADD", "admin", account.id, joint ? "joint account" : "normal account");
                        result = write_reply(socket_fd, line);
                    }
                }
            }
        }
    }
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return result;
}

int store_admin_delete(int socket_fd, uint32_t account_id)
{
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = write_reply(socket_fd, "ERR|Account file is damaged");
    } else {
        off_t target = -1;
        Account account;
        for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
            if (pread_full(fd, &account, sizeof(account), at) != 0)
                break;
            if (account.id == account_id) {
                target = at;
                break;
            }
        }
        if (target < 0) {
            result = write_reply(socket_fd, "ERR|Account not found");
        } else if (account.session_a || account.session_b) {
            result = write_reply(socket_fd, "ERR|Log out account holders before deleting this account");
        } else {
            for (off_t at = target + (off_t)sizeof(Account); at < status.st_size; at += (off_t)sizeof(Account)) {
                Account following;
                if (pread_full(fd, &following, sizeof(following), at) != 0 ||
                    pwrite_full(fd, &following, sizeof(following), at - (off_t)sizeof(Account)) < 0) {
                    result = write_reply(socket_fd, "ERR|Could not compact account file");
                    goto delete_done;
                }
            }
            if (ftruncate(fd, status.st_size - (off_t)sizeof(Account)) < 0)
                result = write_reply(socket_fd, "ERR|Could not finish account deletion");
            else {
                char line[96];
                (void)snprintf(line, sizeof(line), "OK|Deleted account %u", account_id);
                audit_log_event("ACCOUNT_DELETE", "admin", account_id, "account record removed");
                result = write_reply(socket_fd, line);
            }
        }
    }
delete_done:
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return result;
}

int store_admin_modify(int socket_fd, uint32_t account_id, const char *name_a,
                       const char *name_b, const char *phone, int active)
{
    if (!text_valid(name_a, BANK_NAME, 1) || !text_valid(name_b, BANK_NAME, 0) ||
        !text_valid(phone, BANK_PHONE, 0) || (active != 0 && active != 1))
        return write_reply(socket_fd, "ERR|Invalid modification fields");
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = write_reply(socket_fd, "ERR|Account file is damaged");
    } else {
        const char *response = "ERR|Account not found";
        for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
            Account account;
            if (pread_full(fd, &account, sizeof(account), at) != 0)
                break;
            if (account.id != account_id)
                continue;
            if (!active && (account.session_a || account.session_b)) {
                response = "ERR|Log out account holders before deactivating this account";
            } else {
                (void)snprintf(account.name_a, sizeof(account.name_a), "%s", name_a);
                (void)snprintf(account.name_b, sizeof(account.name_b), "%s", account.type == ACCOUNT_JOINT ? name_b : "");
                (void)snprintf(account.phone, sizeof(account.phone), "%s", phone);
                account.active = (uint32_t)active;
                if (pwrite_full(fd, &account, sizeof(account), at) < 0)
                    response = "ERR|Could not update account";
                else {
                    response = "OK|Account updated";
                    audit_log_event("ACCOUNT_MODIFY", "admin", account_id, active ? "account active" : "account inactive");
                }
            }
            break;
        }
        result = write_reply(socket_fd, response);
    }
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return result;
}

static int account_matches(const Account *account, const char *key)
{
    uint32_t id;
    if (parse_u32(key, &id) == 0)
        return account->id == id;
    return strcmp(account->username_a, key) == 0 ||
           (account->type == ACCOUNT_JOINT && strcmp(account->username_b, key) == 0);
}

static int print_accounts(int socket_fd, const char *key)
{
    int fd = open(BANK_ACCOUNTS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Account file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Account file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock account file");
    }
    if (send_line(socket_fd, key == NULL ? "OK|Account list" : "OK|Search results") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    int found = 0;
    for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
        Account account;
        if (pread_full(fd, &account, sizeof(account), at) != 0) {
            (void)lock_range(fd, F_UNLCK, 0, 0);
            close(fd);
            return -1;
        }
        if (key != NULL && !account_matches(&account, key))
            continue;
        char line[512];
        account_line(&account, line, sizeof(line));
        if (send_line(socket_fd, line) < 0) {
            (void)lock_range(fd, F_UNLCK, 0, 0);
            close(fd);
            return -1;
        }
        found++;
    }
    if (!found && send_line(socket_fd, key == NULL ? "No accounts yet" : "No matching account") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return send_line(socket_fd, ".");
}

int store_admin_list(int socket_fd)
{
    return print_accounts(socket_fd, NULL);
}

int store_admin_search(int socket_fd, const char *key)
{
    if (!text_valid(key, BANK_USER, 1))
        return write_reply(socket_fd, "ERR|Search by account number or username");
    return print_accounts(socket_fd, key);
}

int store_admin_add_staff(int socket_fd, const char *role, const char *username, const char *password)
{
    uint32_t wanted_role = strcmp(role, "employee") == 0 ? ROLE_EMPLOYEE :
                           strcmp(role, "manager") == 0 ? ROLE_MANAGER : 0;
    if (wanted_role == 0 || !username_valid(username) || !password_valid(password))
        return write_reply(socket_fd, "ERR|Use employee or manager, a valid username, and a password of at least 8 characters");
    int fd = open(BANK_STAFF_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Staff file unavailable");
    int result = write_reply(socket_fd, "ERR|Could not create staff login");
    if (lock_range(fd, F_WRLCK, 0, 0) == 0) {
        struct stat status;
        if (fstat(fd, &status) == 0 && status.st_size % (off_t)sizeof(Staff) == 0) {
            int duplicate = 0;
            for (off_t offset = 0; offset < status.st_size; offset += (off_t)sizeof(Staff)) {
                Staff current;
                if (pread_full(fd, &current, sizeof(current), offset) != 0) { duplicate = 1; break; }
                if (strcmp(current.username, username) == 0) { duplicate = 1; break; }
            }
            if (!duplicate) {
                Staff staff;
                memset(&staff, 0, sizeof(staff));
                staff.role = wanted_role;
                staff.active = 1;
                (void)snprintf(staff.username, sizeof(staff.username), "%s", username);
                if (make_password_hash(password, staff.password_hash, sizeof(staff.password_hash)) == 0 &&
                    pwrite_full(fd, &staff, sizeof(staff), status.st_size) == 0 && fsync(fd) == 0) {
                    result = write_reply(socket_fd, "OK|Staff login created");
                    audit_log_event("STAFF_ADD", "admin", 0, role);
                } else {
                    int cleanup_result = ftruncate(fd, status.st_size);
                    (void)cleanup_result;
                }
            } else {
                result = write_reply(socket_fd, "ERR|Username is already in use");
            }
        }
        (void)lock_range(fd, F_UNLCK, 0, 0);
    }
    close(fd);
    return result;
}

int store_apply_loan(const Session *session, int64_t amount, uint32_t term_months, uint32_t *loan_id)
{
    if (session == NULL || !session->authenticated ||
        (session->role != ROLE_CUSTOMER && session->role != ROLE_JOINT) ||
        amount <= 0 || term_months == 0 || term_months > 360)
        return BANK_INVALID;
    Account account;
    int account_fd = open(BANK_ACCOUNTS_FILE, O_RDONLY | O_CLOEXEC);
    if (account_fd < 0)
        return BANK_STORAGE;
    int found = find_account(account_fd, session->account_id, &account, NULL);
    close(account_fd);
    if (found != 0)
        return found < 0 ? BANK_STORAGE : BANK_NOT_FOUND;
    if (!account.active)
        return BANK_INACTIVE;
    int fd = open(BANK_LOANS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return BANK_STORAGE;
    int result = BANK_STORAGE;
    if (lock_range(fd, F_WRLCK, 0, 0) == 0) {
        struct stat status;
        if (fstat(fd, &status) == 0 && status.st_size % (off_t)sizeof(Loan) == 0) {
            uint32_t id = 1;
            int valid = 1;
            for (off_t offset = 0; offset < status.st_size; offset += (off_t)sizeof(Loan)) {
                Loan current;
                if (pread_full(fd, &current, sizeof(current), offset) != 0) { valid = 0; break; }
                if (current.id >= id) id = current.id + 1;
            }
            if (valid && id != 0) {
                Loan loan;
                memset(&loan, 0, sizeof(loan));
                loan.id = id;
                loan.account_id = session->account_id;
                loan.status = LOAN_PENDING;
                loan.term_months = term_months;
                loan.principal_cents = amount;
                loan.rate_basis_points = 800;
                (void)snprintf(loan.applicant, sizeof(loan.applicant), "%s", session->username);
                set_timestamp(loan.requested_at, sizeof(loan.requested_at));
                if (pwrite_full(fd, &loan, sizeof(loan), status.st_size) == 0 && fsync(fd) == 0) {
                    *loan_id = id;
                    result = BANK_OK;
                    audit_log_event("LOAN_APPLY", session->username, session->account_id, "loan request submitted");
                } else {
                    int cleanup_result = ftruncate(fd, status.st_size);
                    (void)cleanup_result;
                }
            }
        }
        (void)lock_range(fd, F_UNLCK, 0, 0);
    }
    close(fd);
    return result;
}

int store_list_loans(int socket_fd, const Session *session, int all_accounts)
{
    if (session == NULL || !session->authenticated)
        return write_reply(socket_fd, "ERR|Login required");
    int fd = open(BANK_LOANS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return write_reply(socket_fd, "ERR|Loan file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Loan) != 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Loan file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return write_reply(socket_fd, "ERR|Could not lock loan file");
    }
    if (send_line(socket_fd, "OK|Loan records") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    int rows = 0;
    for (off_t offset = 0; offset < status.st_size; offset += (off_t)sizeof(Loan)) {
        Loan loan;
        if (pread_full(fd, &loan, sizeof(loan), offset) != 0) {
            (void)lock_range(fd, F_UNLCK, 0, 0);
            close(fd);
            return -1;
        }
        if (!all_accounts && loan.account_id != session->account_id)
            continue;
        const char *state = loan.status == LOAN_APPROVED ? "approved" :
                            loan.status == LOAN_REJECTED ? "rejected" : "pending";
        char amount[64], line[256];
        format_money(loan.principal_cents, amount, sizeof(amount));
        (void)snprintf(line, sizeof(line), "Loan %u | account %u | %s | amount %s | term %u months | rate 8.00%% | applicant %s | reviewer %s",
                       loan.id, loan.account_id, state, amount, loan.term_months,
                       loan.applicant, loan.reviewer[0] ? loan.reviewer : "-");
        if (send_line(socket_fd, line) < 0) {
            (void)lock_range(fd, F_UNLCK, 0, 0);
            close(fd);
            return -1;
        }
        rows++;
    }
    if (!rows && send_line(socket_fd, "No loan records") < 0) {
        (void)lock_range(fd, F_UNLCK, 0, 0);
        close(fd);
        return -1;
    }
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return send_line(socket_fd, ".");
}

int store_review_loan(int socket_fd, const Session *session, uint32_t loan_id, int approve)
{
    if (session == NULL || (session->role != ROLE_MANAGER && session->role != ROLE_ADMIN))
        return write_reply(socket_fd, "ERR|Only a manager or administrator can review loans");
    pthread_mutex_lock(&loan_review_mutex);
    int loan_fd = open(BANK_LOANS_FILE, O_RDWR | O_CLOEXEC);
    int result = write_reply(socket_fd, "ERR|Loan request not found");
    if (loan_fd < 0) {
        pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, "ERR|Loan file unavailable");
    }
    struct stat status;
    if (fstat(loan_fd, &status) < 0 || status.st_size % (off_t)sizeof(Loan) != 0) {
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, "ERR|Loan file is damaged");
    }
    off_t loan_offset = -1;
    Loan loan;
    for (off_t offset = 0; offset < status.st_size; offset += (off_t)sizeof(Loan)) {
        if (pread_full(loan_fd, &loan, sizeof(loan), offset) != 0)
            break;
        if (loan.id == loan_id) { loan_offset = offset; break; }
    }
    if (loan_offset < 0 || loan.status != LOAN_PENDING) {
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, loan_offset < 0 ? "ERR|Loan request not found" : "ERR|Loan request was already reviewed");
    }
    loan.status = approve ? LOAN_APPROVED : LOAN_REJECTED;
    (void)snprintf(loan.reviewer, sizeof(loan.reviewer), "%s", session->username);
    set_timestamp(loan.reviewed_at, sizeof(loan.reviewed_at));
    if (!approve) {
        result = pwrite_full(loan_fd, &loan, sizeof(loan), loan_offset) == 0 && fsync(loan_fd) == 0 ?
                 write_reply(socket_fd, "OK|Loan rejected") : write_reply(socket_fd, "ERR|Could not update loan record");
        audit_log_event("LOAN_REJECT", session->username, loan.account_id, "loan request rejected");
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return result;
    }
    int account_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (account_fd < 0) {
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, "ERR|Account file unavailable");
    }
    off_t account_offset = 0;
    int found = find_account(account_fd, loan.account_id, NULL, &account_offset);
    if (found != 0 || lock_range(account_fd, F_WRLCK, account_offset, (off_t)sizeof(Account)) < 0) {
        close(account_fd); close(loan_fd); pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, "ERR|Could not lock loan account");
    }
    Account account;
    if (pread_full(account_fd, &account, sizeof(account), account_offset) != 0 || !account.active ||
        account.balance_cents > INT64_MAX - loan.principal_cents) {
        (void)lock_range(account_fd, F_UNLCK, account_offset, (off_t)sizeof(Account));
        close(account_fd); close(loan_fd); pthread_mutex_unlock(&loan_review_mutex);
        return write_reply(socket_fd, "ERR|Account inactive or balance overflow");
    }
    int64_t before = account.balance_cents;
    account.balance_cents += loan.principal_cents;
    Transaction transaction;
    memset(&transaction, 0, sizeof(transaction));
    transaction.account_id = account.id;
    transaction.amount_cents = loan.principal_cents;
    transaction.before_cents = before;
    transaction.after_cents = account.balance_cents;
    (void)snprintf(transaction.actor, sizeof(transaction.actor), "%s", session->username);
    (void)snprintf(transaction.kind, sizeof(transaction.kind), "loan");
    set_timestamp(transaction.timestamp, sizeof(transaction.timestamp));
    int committed = commit_financial(&account, account_offset, &transaction, &loan, loan_offset) == 0;
    (void)lock_range(account_fd, F_UNLCK, account_offset, (off_t)sizeof(Account));
    close(account_fd); close(loan_fd);
    pthread_mutex_unlock(&loan_review_mutex);
    if (committed) {
        audit_log_event("LOAN_APPROVE", session->username, account.id, "loan approved and disbursed");
        return write_reply(socket_fd, "OK|Loan approved and principal credited");
    }
    return write_reply(socket_fd, "ERR|Could not commit loan approval");
}

int store_staff_transaction(int socket_fd, const Session *session, uint32_t account_id,
                            int64_t amount, int withdraw)
{
    if (session == NULL || (session->role != ROLE_EMPLOYEE && session->role != ROLE_MANAGER &&
                            session->role != ROLE_ADMIN) || amount <= 0)
        return write_reply(socket_fd, "ERR|Invalid staff transaction");
    Session customer;
    memset(&customer, 0, sizeof(customer));
    customer.authenticated = 1;
    customer.role = ROLE_CUSTOMER;
    customer.account_id = account_id;
    (void)snprintf(customer.username, sizeof(customer.username), "%s", session->username);
    int64_t balance = 0;
    int result = withdraw ? store_withdraw(&customer, amount, &balance) : store_deposit(&customer, amount, &balance);
    if (result != BANK_OK)
        return write_reply(socket_fd, result == BANK_INSUFFICIENT ? "ERR|Insufficient funds" :
                           result == BANK_NOT_FOUND ? "ERR|Account not found" : "ERR|Transaction failed");
    char money[64], line[128];
    format_money(balance, money, sizeof(money));
    (void)snprintf(line, sizeof(line), "OK|Staff transaction completed. Balance %s", money);
    return write_reply(socket_fd, line);
}
