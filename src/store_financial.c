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

int store_commit_financial(Account *account, off_t account_offset,
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

static int change_balance(const Session *session, int64_t amount, int withdraw, int64_t *balance)
{
    if (session == NULL || !session->authenticated || session->administrator || amount <= 0)
        return BANK_INVALID;
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
            store_set_timestamp(transaction.timestamp, sizeof(transaction.timestamp));
            if (store_commit_financial(&account, at, &transaction, NULL, 0) < 0) {
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

int store_history(const Session *session, int socket_fd)
{
    int fd = open(BANK_TRANSACTIONS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return store_write_reply(socket_fd, "ERR|Transaction file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Transaction) != 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Transaction file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock transaction file");
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

int store_staff_transaction(int socket_fd, const Session *session, uint32_t account_id,
                            int64_t amount, int withdraw)
{
    if (session == NULL || (session->role != ROLE_EMPLOYEE && session->role != ROLE_MANAGER &&
                            session->role != ROLE_ADMIN) || amount <= 0)
        return store_write_reply(socket_fd, "ERR|Invalid staff transaction");
    Session customer;
    memset(&customer, 0, sizeof(customer));
    customer.authenticated = 1;
    customer.role = ROLE_CUSTOMER;
    customer.account_id = account_id;
    (void)snprintf(customer.username, sizeof(customer.username), "%s", session->username);
    int64_t balance = 0;
    int result = withdraw ? store_withdraw(&customer, amount, &balance) : store_deposit(&customer, amount, &balance);
    if (result != BANK_OK)
        return store_write_reply(socket_fd, result == BANK_INSUFFICIENT ? "ERR|Insufficient funds" :
                           result == BANK_NOT_FOUND ? "ERR|Account not found" : "ERR|Transaction failed");
    char money[64], line[128];
    format_money(balance, money, sizeof(money));
    (void)snprintf(line, sizeof(line), "OK|Staff transaction completed. Balance %s", money);
    return store_write_reply(socket_fd, line);
}
