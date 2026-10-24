#ifndef SERVER_INTERNAL_H
#define SERVER_INTERNAL_H

#include <sys/types.h>

void audit_writer(int read_fd);
void audit_set_fd(int fd);
void audit_stop(pid_t writer_pid);

#endif
