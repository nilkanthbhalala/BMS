#ifndef STORE_INTERNAL_H
#define STORE_INTERNAL_H

#include "bank.h"

int store_text_valid(const char *text, size_t maximum, int required);
int store_username_valid(const char *username);
int store_password_valid(const char *password);
void store_set_timestamp(char *buffer, size_t capacity);
int store_find_account(int fd, uint32_t account_id, Account *account, off_t *offset);
int store_write_reply(int fd, const char *message);
int store_commit_financial(Account *account, off_t account_offset,
                           Transaction *transaction, Loan *loan, off_t loan_offset);

#endif
