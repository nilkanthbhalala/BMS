#include "bank.h"

#include <string.h>

int manager_review_loan(int socket_fd, const Session *session, char **fields)
{
    uint32_t loan_id;
    if (session == NULL || (session->role != ROLE_MANAGER && session->role != ROLE_ADMIN))
        return send_reply(socket_fd, "ERR|Manager login required");
    if (parse_u32(fields[1], &loan_id) < 0 ||
        (strcmp(fields[2], "approve") != 0 && strcmp(fields[2], "reject") != 0))
        return send_reply(socket_fd, "ERR|Use REVIEW|loan-number|approve-or-reject");
    return store_review_loan(socket_fd, session, loan_id, strcmp(fields[2], "approve") == 0);
}

int dispatch_manager(int fd, char **fields, int count, const Session *session)
{
    if (strcmp(fields[0], "REVIEW") == 0 && count == 3)
        return manager_review_loan(fd, session, fields);
    return dispatch_bank_employee(fd, fields, count, session);
}
