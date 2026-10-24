#include "bank.h"

#include <stdio.h>
#include <string.h>

static const char *customer_status(int status)
{
    switch (status) {
        case BANK_NOT_FOUND: return "Account not found";
        case BANK_INACTIVE: return "Account is inactive";
        case BANK_INSUFFICIENT: return "Insufficient funds";
        case BANK_INVALID: return "Invalid value or password";
        case BANK_BUSY: return "Account is already in use";
        default: return "Storage operation failed";
    }
}

static int customer_reply_status(int fd, int status, const char *success)
{
    char response[256];
    if (status == BANK_OK)
        (void)snprintf(response, sizeof(response), "OK|%s", success);
    else
        (void)snprintf(response, sizeof(response), "ERR|%s", customer_status(status));
    return send_reply(fd, response);
}

int customer_apply_loan(int socket_fd, const Session *session, char **fields)
{
    int64_t amount;
    uint32_t months, loan_id;
    if (parse_money(fields[1], &amount) < 0 || parse_u32(fields[2], &months) < 0)
        return send_reply(socket_fd, "ERR|Use a positive amount and term in months");
    int status = store_apply_loan(session, amount, months, &loan_id);
    if (status != BANK_OK)
        return send_reply(socket_fd, "ERR|Loan request could not be submitted");
    char response[96];
    (void)snprintf(response, sizeof(response), "OK|Loan request %u submitted", loan_id);
    return send_reply(socket_fd, response);
}

int customer_show_loans(int socket_fd, const Session *session)
{
    if (session == NULL || (session->role != ROLE_CUSTOMER && session->role != ROLE_JOINT))
        return send_reply(socket_fd, "ERR|Customer login required");
    return store_list_loans(socket_fd, session, 0);
}

int dispatch_customer(int fd, char **fields, int count, const Session *session)
{
    char message[128];
    int64_t amount, balance;
    if (strcmp(fields[0], "BALANCE") == 0 && count == 1) {
        int status = store_get_balance(session, &balance);
        if (status != BANK_OK)
            return customer_reply_status(fd, status, "");
        char money[64];
        format_money(balance, money, sizeof(money));
        (void)snprintf(message, sizeof(message), "OK|Available balance: %s", money);
        return send_reply(fd, message);
    }
    if ((strcmp(fields[0], "DEPOSIT") == 0 || strcmp(fields[0], "WITHDRAW") == 0) && count == 2) {
        if (parse_money(fields[1], &amount) < 0 || amount <= 0)
            return send_reply(fd, "ERR|Enter a positive amount with at most two decimal places");
        int withdrawal = strcmp(fields[0], "WITHDRAW") == 0;
        int status = withdrawal ? store_withdraw(session, amount, &balance) : store_deposit(session, amount, &balance);
        if (status != BANK_OK)
            return customer_reply_status(fd, status, "");
        char money[64];
        format_money(balance, money, sizeof(money));
        (void)snprintf(message, sizeof(message), "OK|%s successful. New balance: %s",
                       withdrawal ? "Withdrawal" : "Deposit", money);
        return send_reply(fd, message);
    }
    if (strcmp(fields[0], "DETAILS") == 0 && count == 1) {
        Account account;
        int status = store_get_account(session, &account);
        if (status != BANK_OK)
            return customer_reply_status(fd, status, "");
        char line[512];
        if (account.type == ACCOUNT_JOINT)
            (void)snprintf(line, sizeof(line), "OK|Account %u | Joint | %s and %s | Users %s and %s | Phone %s",
                           account.id, account.name_a, account.name_b, account.username_a,
                           account.username_b, account.phone[0] ? account.phone : "-");
        else
            (void)snprintf(line, sizeof(line), "OK|Account %u | Normal | %s | User %s | Phone %s",
                           account.id, account.name_a, account.username_a,
                           account.phone[0] ? account.phone : "-");
        return send_reply(fd, line);
    }
    if (strcmp(fields[0], "HISTORY") == 0 && count == 1)
        return store_history(session, fd);
    if (strcmp(fields[0], "CHPASS") == 0 && count == 3) {
        int status = store_change_password(session, fields[1], fields[2]);
        if (status == BANK_OK)
            return send_reply(fd, "OK|Password changed");
        if (status == BANK_INVALID)
            return send_reply(fd, "ERR|Old password is wrong or new password is too short");
        return customer_reply_status(fd, status, "");
    }
    if (strcmp(fields[0], "APPLY_LOAN") == 0 && count == 3)
        return customer_apply_loan(fd, session, fields);
    if (strcmp(fields[0], "LOANS") == 0 && count == 1)
        return customer_show_loans(fd, session);
    return send_reply(fd, "ERR|Unknown customer command");
}
