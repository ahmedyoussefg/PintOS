#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/synch.h"

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
  /*Go3: this was just for trial, remove till before thread_exit(); line*/
  int *sys_call_type= (int *)f->esp;

  /* Inside each syscall wrapper : call validate_void_ptr: check if ptr not null, 
   * check if user vaddr , ptr correctly mapped to virtual address*/
  switch (*sys_call_type){
    case SYS_WAIT:
      // handle wait
      pid_t pid = (pid_t) *(sys_call_type+1); 
      int child_exit_status = wait_wrapper(pid);
      break;
    case SYS_EXIT:
      // handle exit
      int status = (int) *(sys_call_type+1); 
      exit(status);
      break;
  }
  //  TODO: ....continue rest of cases........ for remaining  syscalls
  thread_exit ();
}

// OUR syscalls implementation:
/* Waits for a child process pid and retrieves the child's exit status. */
int wait_wrapper (pid_t pid) {
  return wait(pid);
}

int wait(pid_t pid){
  return process_wait((tid_t) pid); 
}

void halt_wrapper(void)
{
  halt();
}

void halt(void){
  // handle halt
  shutdown_power_off();
}

void exit_wrapper(int status) {
  exit(status);
}
void exit(int status){
  // release all resources (close files USING close sys call) / resources using process_exit()
  // make sure no leaks
  // wake up all children (if exist)
  struct thread* current= thread_current();
  process_exit();
  
  // TODO: now iterate over each element in open_file and call close(e->fd)
  if (current->parent_process != NULL){
    struct thread * parent= current->parent_process;
    if(parent->waiting_on_which==current->tid){
      parent->child_status_after_wakeup=status;
      semaup(&parent->wait_child);
    }
    list_remove(&current->child_elem);
  }

  // waking up all childrens
  struct list_elem *head= list_begin(&current->child_processes);
  if (head != list_end (&current->child_processes)) 
  {
    struct list_elem *e;
    struct thread *t;
    for (e = list_next (head); e != list_end (&current->child_processes); e = list_next (e))
    {
      t=list_entry(e,struct thread, child_elem);
      sema_up(&t->parent_child_sync);
    }
  }


  // call exit_thread();
  thread_exit();  
}
