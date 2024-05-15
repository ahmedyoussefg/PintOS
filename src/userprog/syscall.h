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
void create_wrapper(struct intr_frame *f);
bool create(const char *file, unsigned initial_size);
void remove_wrapper(struct intr_frame *f);
bool remove(const char *file);
void open_wrapper(struct intr_frame *f);
int open(const char *file);
void close_wrapper(struct intr_frame *f);
void close(int fd);
void filesize_wrapper(struct intr_frame *f);
int size(int fd);
void read_wrapper(struct intr_frame *f);
int read(int fd, void *buffer, unsigned size);
void write_wrapper(struct intr_frame *f);
int write(int fd, const void *buffer, unsigned size);
void seek_wrapper(struct intr_frame *f);
void seek(int fd, unsigned position);
void tell_wrapper(struct intr_frame *f);
unsigned tell(int fd);
struct file *get_file(int fd);
#endif /* userprog/syscall.h */
