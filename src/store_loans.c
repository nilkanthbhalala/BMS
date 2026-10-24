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

static pthread_mutex_t loan_review_mutex = PTHREAD_MUTEX_INITIALIZER;

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
    int found = store_find_account(account_fd, session->account_id, &account, NULL);
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
                store_set_timestamp(loan.requested_at, sizeof(loan.requested_at));
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
        return store_write_reply(socket_fd, "ERR|Login required");
    int fd = open(BANK_LOANS_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return store_write_reply(socket_fd, "ERR|Loan file unavailable");
    struct stat status;
    if (fstat(fd, &status) < 0 || status.st_size % (off_t)sizeof(Loan) != 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Loan file is damaged");
    }
    if (lock_range(fd, F_RDLCK, 0, 0) < 0) {
        close(fd);
        return store_write_reply(socket_fd, "ERR|Could not lock loan file");
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
        return store_write_reply(socket_fd, "ERR|Only a manager or administrator can review loans");
    pthread_mutex_lock(&loan_review_mutex);
    int loan_fd = open(BANK_LOANS_FILE, O_RDWR | O_CLOEXEC);
    int result = store_write_reply(socket_fd, "ERR|Loan request not found");
    if (loan_fd < 0) {
        pthread_mutex_unlock(&loan_review_mutex);
        return store_write_reply(socket_fd, "ERR|Loan file unavailable");
    }
    struct stat status;
    if (fstat(loan_fd, &status) < 0 || status.st_size % (off_t)sizeof(Loan) != 0) {
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return store_write_reply(socket_fd, "ERR|Loan file is damaged");
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
        return store_write_reply(socket_fd, loan_offset < 0 ? "ERR|Loan request not found" : "ERR|Loan request was already reviewed");
    }
    loan.status = approve ? LOAN_APPROVED : LOAN_REJECTED;
    (void)snprintf(loan.reviewer, sizeof(loan.reviewer), "%s", session->username);
    store_set_timestamp(loan.reviewed_at, sizeof(loan.reviewed_at));
    if (!approve) {
        result = pwrite_full(loan_fd, &loan, sizeof(loan), loan_offset) == 0 && fsync(loan_fd) == 0 ?
                 store_write_reply(socket_fd, "OK|Loan rejected") : store_write_reply(socket_fd, "ERR|Could not update loan record");
        audit_log_event("LOAN_REJECT", session->username, loan.account_id, "loan request rejected");
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return result;
    }
    int account_fd = open(BANK_ACCOUNTS_FILE, O_RDWR | O_CLOEXEC);
    if (account_fd < 0) {
        close(loan_fd);
        pthread_mutex_unlock(&loan_review_mutex);
        return store_write_reply(socket_fd, "ERR|Account file unavailable");
    }
    off_t account_offset = 0;
    int found = store_find_account(account_fd, loan.account_id, NULL, &account_offset);
    if (found != 0 || lock_range(account_fd, F_WRLCK, account_offset, (off_t)sizeof(Account)) < 0) {
        close(account_fd); close(loan_fd); pthread_mutex_unlock(&loan_review_mutex);
        return store_write_reply(socket_fd, "ERR|Could not lock loan account");
    }
    Account account;
    if (pread_full(account_fd, &account, sizeof(account), account_offset) != 0 || !account.active ||
        account.balance_cents > INT64_MAX - loan.principal_cents) {
        (void)lock_range(account_fd, F_UNLCK, account_offset, (off_t)sizeof(Account));
        close(account_fd); close(loan_fd); pthread_mutex_unlock(&loan_review_mutex);
        return store_write_reply(socket_fd, "ERR|Account inactive or balance overflow");
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
    store_set_timestamp(transaction.timestamp, sizeof(transaction.timestamp));
    int committed = store_commit_financial(&account, account_offset, &transaction, &loan, loan_offset) == 0;
    (void)lock_range(account_fd, F_UNLCK, account_offset, (off_t)sizeof(Account));
    close(account_fd); close(loan_fd);
    pthread_mutex_unlock(&loan_review_mutex);
    if (committed) {
        audit_log_event("LOAN_APPROVE", session->username, account.id, "loan approved and disbursed");
        return store_write_reply(socket_fd, "OK|Loan approved and principal credited");
    }
    return store_write_reply(socket_fd, "ERR|Could not commit loan approval");
}
