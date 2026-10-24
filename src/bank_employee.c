#include "bank.h"

#include <string.h>

int bank_employee_transaction(int socket_fd, const Session *session, char **fields, int withdraw)
{
    uint32_t account_id;
    int64_t amount;
    if (session == NULL || session->role != ROLE_EMPLOYEE)
        return send_reply(socket_fd, "ERR|Bank employee login required");
    if (parse_u32(fields[1], &account_id) < 0 || parse_money(fields[2], &amount) < 0 || amount <= 0)
        return send_reply(socket_fd, "ERR|Use a valid account number and positive amount");
    return store_staff_transaction(socket_fd, session, account_id, amount, withdraw);
}

int dispatch_bank_employee(int fd, char **fields, int count, const Session *session)
{
    if (strcmp(fields[0], "LIST") == 0 && count == 1)
        return store_admin_list(fd);
    if (strcmp(fields[0], "SEARCH") == 0 && count == 2)
        return store_admin_search(fd, fields[1]);
    if (strcmp(fields[0], "LOANS") == 0 && count == 1)
        return store_list_loans(fd, session, 1);
    if (strcmp(fields[0], "CHPASS") == 0 && count == 3) {
        int status = store_change_password(session, fields[1], fields[2]);
        if (status == BANK_OK)
            return send_reply(fd, "OK|Password changed");
        return send_reply(fd, status == BANK_INVALID ? "ERR|Old password is wrong or new password is too short" :
                          "ERR|Could not change password");
    }
    if ((strcmp(fields[0], "DEPOSIT") == 0 || strcmp(fields[0], "WITHDRAW") == 0) && count == 3)
        return bank_employee_transaction(fd, session, fields, strcmp(fields[0], "WITHDRAW") == 0);
    return send_reply(fd, "ERR|Operation is not available for this role");
}
