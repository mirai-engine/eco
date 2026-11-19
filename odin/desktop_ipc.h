#ifndef ECO_DESKTOP_IPC_H
#define ECO_DESKTOP_IPC_H

void eco_install_signals(void);
int eco_stopping(void);
int eco_check_private_dir(const char *name);
int eco_lock_local(const char *name);
int eco_prepare_socket(const char *name);
int eco_listen_local(const char *name);
int eco_accept_local(int listener);
int eco_wait(int fd, int timeout);

#endif
