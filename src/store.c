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

int store_text_valid(const char *text, size_t maximum, int required)
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

int store_username_valid(const char *username)
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

int store_password_valid(const char *password)
{
    size_t length = strlen(password);
    if (length < 8 || length >= 96)
        return 0;
    return store_text_valid(password, 96, 1);
}

void store_set_timestamp(char *buffer, size_t capacity)
{
    time_t now = time(NULL);
    struct tm value;
    if (localtime_r(&now, &value) == NULL) {
        (void)snprintf(buffer, capacity, "unknown");
        return;
    }
    (void)strftime(buffer, capacity, "%Y-%m-%d %H:%M:%S", &value);
}

int store_find_account(int fd, uint32_t account_id, Account *account, off_t *offset)
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

int store_write_reply(int fd, const char *message)
{
    return send_reply(fd, message);
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
            if (store_find_account(fd, session->account_id, NULL, &at) == 0 &&
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
    int found = store_find_account(fd, session->account_id, account, NULL);
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

int store_change_password(const Session *session, const char *old_password, const char *new_password)
{
    if (session == NULL || !session->authenticated || !store_password_valid(new_password))
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
    int found = store_find_account(fd, session->account_id, NULL, &at);
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
