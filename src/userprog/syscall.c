#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  int sys_call_type = (int)f->esp;
  if (sys_call_type == SYS_WAIT){
    // handle wait
    syscall_wait();
  }
  else if (sys_call_type == SYS_EXIT) {
    // handle exit
    syscall_exit();
  }
  //  TODO: ....continue if elses........ for remaining  syscalls
  thread_exit ();
}

// OUR syscalls implementation:
int
syscall_wait(pid_t pid) {

}

void
syscall_exit(int status) {

}