#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"

typedef int pid_t;
void syscall_init (void);
void validate_void_ptr(void *ptr);
void wait_wrapper (struct intr_frame *f);
int wait(pid_t pid);
void halt_wrapper(void);
void halt(void);
void exit_wrapper(struct intr_frame *f);
void exit(int status);
pid_t execute(char *file_name);
void execute_wrapper(struct intr_frame *f);
bool validate_file_name(const char *file_name);
struct file *get_file(int fd);

#endif /* userprog/syscall.h */
