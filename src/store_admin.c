#define _GNU_SOURCE
#include "bank.h"
#include "store_internal.h"

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

int store_admin_change_password(const char *old_password, const char *new_password)
{
    if (!store_password_valid(new_password))
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

static int usernames_available(int fd, const char *first, const char *second, uint32_t except_id)
{
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0)
        return -1;
    for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
        Account account;
        if (pread_full(fd, &account, sizeof(account), at) != 0)
            return -1;
        if (account.id == except_id)
            continue;
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
    if (!store_text_valid(name_a, BANK_NAME, 1) || !store_username_valid(username_a) || !store_password_valid(password_a) ||
        !store_text_valid(phone, BANK_PHONE, 0) || parse_money(money_text, &opening_balance) < 0)
        return store_write_reply(socket_fd, "ERR|Invalid account fields; passwords need at least 8 characters");
    if (joint && (!store_text_valid(name_b, BANK_NAME, 1) || !store_username_valid(username_b) ||
                  !store_password_valid(password_b) || strcmp(username_a, username_b) == 0))
        return store_write_reply(socket_fd, "ERR|Joint accounts need two distinct valid users and passwords");

    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return store_write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result = -1;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = store_write_reply(socket_fd, "ERR|Account file is damaged");
    } else {
        int available = usernames_available(fd, username_a, joint ? username_b : "", 0);
        if (available <= 0) {
            result = store_write_reply(socket_fd, available == 0 ? "ERR|A username is already in use" : "ERR|Account file read failed");
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
                result = store_write_reply(socket_fd, "ERR|Account number space is exhausted");
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
                    result = store_write_reply(socket_fd, "ERR|Could not create account");
                } else {
                    Transaction opening;
                    memset(&opening, 0, sizeof(opening));
                    opening.account_id = account.id;
                    opening.amount_cents = opening_balance;
                    opening.before_cents = 0;
                    opening.after_cents = opening_balance;
                    (void)snprintf(opening.actor, sizeof(opening.actor), "admin");
                    (void)snprintf(opening.kind, sizeof(opening.kind), "opening");
                    store_set_timestamp(opening.timestamp, sizeof(opening.timestamp));
                    if (store_commit_financial(&account, status.st_size, &opening, NULL, 0) < 0) {
                        result = store_write_reply(socket_fd, "ERR|Could not create account");
                    } else {
                        char line[128];
                        (void)snprintf(line, sizeof(line), "OK|Created account %u", account.id);
                        audit_log_event("ACCOUNT_ADD", "admin", account.id, joint ? "joint account" : "normal account");
                        result = store_write_reply(socket_fd, line);
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
        return store_write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = store_write_reply(socket_fd, "ERR|Account file is damaged");
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
            result = store_write_reply(socket_fd, "ERR|Account not found");
        } else if (account.session_a || account.session_b) {
            result = store_write_reply(socket_fd, "ERR|Log out account holders before deleting this account");
        } else {
            for (off_t at = target + (off_t)sizeof(Account); at < status.st_size; at += (off_t)sizeof(Account)) {
                Account following;
                if (pread_full(fd, &following, sizeof(following), at) != 0 ||
                    pwrite_full(fd, &following, sizeof(following), at - (off_t)sizeof(Account)) < 0) {
                    result = store_write_reply(socket_fd, "ERR|Could not compact account file");
                    goto delete_done;
                }
            }
            if (ftruncate(fd, status.st_size - (off_t)sizeof(Account)) < 0)
                result = store_write_reply(socket_fd, "ERR|Could not finish account deletion");
            else {
                char line[96];
                (void)snprintf(line, sizeof(line), "OK|Deleted account %u", account_id);
                audit_log_event("ACCOUNT_DELETE", "admin", account_id, "account record removed");
                result = store_write_reply(socket_fd, line);
            }
        }
    }
delete_done:
    (void)lock_range(fd, F_UNLCK, 0, 0);
    close(fd);
    return result;
}

int store_admin_modify(int socket_fd, uint32_t account_id, const char *name_a,
                       const char *name_b, const char *username_a,
                       const char *username_b, const char *phone, int active)
{
    if (!store_text_valid(name_a, BANK_NAME, 1) || !store_text_valid(name_b, BANK_NAME, 0) ||
        !store_username_valid(username_a) || !store_text_valid(username_b, BANK_USER, 0) ||
        !store_text_valid(phone, BANK_PHONE, 0) || (active != 0 && active != 1))
        return store_write_reply(socket_fd, "ERR|Invalid modification fields");
    int fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return store_write_reply(socket_fd, "ERR|Account file unavailable");
    if (lock_range(fd, F_WRLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock account file");
    }
    struct stat status;
    int result;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        result = store_write_reply(socket_fd, "ERR|Account file is damaged");
    } else {
        const char *response = "ERR|Account not found";
        for (off_t at = 0; at < status.st_size; at += (off_t)sizeof(Account)) {
            Account account;
            if (pread_full(fd, &account, sizeof(account), at) != 0)
                break;
            if (account.id != account_id)
                continue;
            if (account.type != ACCOUNT_NORMAL && account.type != ACCOUNT_JOINT) {
                response = "ERR|Account record is invalid";
            } else if ((account.type == ACCOUNT_JOINT &&
                        (!store_username_valid(username_b) || strcmp(username_a, username_b) == 0)) ||
                       (account.type == ACCOUNT_NORMAL && username_b[0] != '\0')) {
                response = account.type == ACCOUNT_JOINT ?
                           "ERR|Joint accounts need two distinct valid usernames" :
                           "ERR|Normal accounts must have a blank second username";
            } else if ((strcmp(account.username_a, username_a) != 0 ||
                        strcmp(account.username_b, account.type == ACCOUNT_JOINT ? username_b : "") != 0) &&
                       (account.session_a || account.session_b)) {
                response = "ERR|Log out account holders before changing usernames";
            } else if (!active && (account.session_a || account.session_b)) {
                response = "ERR|Log out account holders before deactivating this account";
            } else {
                int available = usernames_available(fd, username_a,
                                                    account.type == ACCOUNT_JOINT ? username_b : "",
                                                    account.id);
                if (available <= 0) {
                    response = available == 0 ? "ERR|A username is already in use" :
                               "ERR|Account file read failed";
                    break;
                }
                (void)snprintf(account.name_a, sizeof(account.name_a), "%s", name_a);
                (void)snprintf(account.name_b, sizeof(account.name_b), "%s", account.type == ACCOUNT_JOINT ? name_b : "");
                (void)snprintf(account.username_a, sizeof(account.username_a), "%s", username_a);
                (void)snprintf(account.username_b, sizeof(account.username_b), "%s",
                               account.type == ACCOUNT_JOINT ? username_b : "");
                (void)snprintf(account.phone, sizeof(account.phone), "%s", phone);
                account.active = (uint32_t)active;
                if (pwrite_full(fd, &account, sizeof(account), at) < 0)
                    response = "ERR|Could not update account";
                else {
                    response = "OK|Account updated";
                    audit_log_event("ACCOUNT_MODIFY", "admin", account_id,
                                    active ? "account details and usernames updated; active" :
                                             "account details and usernames updated; inactive");
                }
            }
            break;
        }
        result = store_write_reply(socket_fd, response);
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
        return store_write_reply(socket_fd, "ERR|Account file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Account) != 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Account file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock account file");
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
    if (!store_text_valid(key, BANK_USER, 1))
        return store_write_reply(socket_fd, "ERR|Search by account number or username");
    return print_accounts(socket_fd, key);
}

int store_admin_add_staff(int socket_fd, const char *role, const char *username, const char *password)
{
    uint32_t wanted_role = strcmp(role, "employee") == 0 ? ROLE_EMPLOYEE :
                           strcmp(role, "manager") == 0 ? ROLE_MANAGER : 0;
    if (wanted_role == 0 || !store_username_valid(username) || !store_password_valid(password))
        return store_write_reply(socket_fd, "ERR|Use employee or manager, a valid username, and a password of at least 8 characters");
    int fd = open(BANK_STAFF_FILE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return store_write_reply(socket_fd, "ERR|Staff file unavailable");
    int result = store_write_reply(socket_fd, "ERR|Could not create staff login");
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
                    result = store_write_reply(socket_fd, "OK|Staff login created");
                    audit_log_event("STAFF_ADD", "admin", 0, role);
                } else {
                    int cleanup_result = ftruncate(fd, status.st_size);
                    (void)cleanup_result;
                }
            } else {
                result = store_write_reply(socket_fd, "ERR|Username is already in use");
            }
        }
        (void)lock_range(fd, F_UNLCK, 0, 0);
    }
    close(fd);
    return result;
}
