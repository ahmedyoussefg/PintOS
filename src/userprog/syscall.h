#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void excecute_wrapper(struct intr_frame *f);



#endif /* userprog/syscall.h */
