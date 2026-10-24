#include "bank.h"

#include <string.h>

int administrator_add_staff(int socket_fd, const Session *session, char **fields)
{
    if (session == NULL || session->role != ROLE_ADMIN)
        return send_reply(socket_fd, "ERR|Administrator login required");
    return store_admin_add_staff(socket_fd, fields[1], fields[2], fields[3]);
}

int dispatch_administrator(int fd, char **fields, int count, const Session *session)
{
    uint32_t account_id;
    if (strcmp(fields[0], "LIST") == 0 && count == 1)
        return store_admin_list(fd);
    if (strcmp(fields[0], "SEARCH") == 0 && count == 2)
        return store_admin_search(fd, fields[1]);
    if (strcmp(fields[0], "ADD_NORMAL") == 0 && count == 6)
        return store_admin_add(fd, 0, fields);
    if (strcmp(fields[0], "ADD_JOINT") == 0 && count == 9)
        return store_admin_add(fd, 1, fields);
    if (strcmp(fields[0], "DELETE") == 0 && count == 2) {
        if (parse_u32(fields[1], &account_id) < 0)
            return send_reply(fd, "ERR|Invalid account number");
        return store_admin_delete(fd, account_id);
    }
    if (strcmp(fields[0], "MODIFY") == 0 && count == 6) {
        if (parse_u32(fields[1], &account_id) < 0 ||
            (strcmp(fields[5], "0") != 0 && strcmp(fields[5], "1") != 0))
            return send_reply(fd, "ERR|Use account number and active value 0 or 1");
        return store_admin_modify(fd, account_id, fields[2], fields[3], fields[4], fields[5][0] - '0');
    }
    if (strcmp(fields[0], "CHPASS") == 0 && count == 3) {
        int status = store_admin_change_password(fields[1], fields[2]);
        return send_reply(fd, status == 0 ? "OK|Administrator password changed" :
                          "ERR|Old password is wrong or new password is too short");
    }
    if (strcmp(fields[0], "ADD_STAFF") == 0 && count == 4)
        return administrator_add_staff(fd, session, fields);
    if (strcmp(fields[0], "LOANS") == 0 && count == 1)
        return store_list_loans(fd, session, 1);
    if (strcmp(fields[0], "REVIEW") == 0 && count == 3)
        return manager_review_loan(fd, session, fields);
    return send_reply(fd, "ERR|Unknown administrator command");
}
