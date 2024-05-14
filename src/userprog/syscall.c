#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);

void validate_void_ptr(void *ptr){
  uint32_t * check =lookup_page(thread_current()->pagedir, ptr, false);
  if (ptr == NULL && !is_user_vaddr(ptr) && check == NULL ){
    exit(-1); // error
  }
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  validate_void_ptr(f->esp);
  int *sys_call_type= (int *)f->esp;

  /* Inside each syscall wrapper : call validate_void_ptr: check if ptr not null, 
   * check if user vaddr , ptr correctly mapped to virtual address*/
  switch (*sys_call_type){
    case SYS_WAIT:
      // handle wait
      wait_wrapper(f);
      break;
    case SYS_EXIT:
      // handle exit
      exit_wrapper(f);
      break;
  }
  //  TODO: ....continue rest of cases........ for remaining  syscalls
  thread_exit ();
}

// OUR syscalls implementation:
/* Waits for a child process pid and retrieves the child's exit status. */
void wait_wrapper (struct intr_frame *f) {
  tid_t * ptr=(tid_t*)f->esp+1;
  validate_void_ptr(ptr);
  pid_t pid = (pid_t) *ptr;
  f->eax=wait(pid);   // return value
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

void exit_wrapper(struct intr_frame *f) {
  int * ptr=(int*)f->esp+1;
  validate_void_ptr(ptr);
  int status = (int) *ptr; 
  exit(status);
}
void exit(int status){
  // release all resources (close files USING close sys call) / resources using process_exit()
  // make sure no leaks
  // wake up all children (if exist)
  struct thread* current= thread_current();
  // process_exit(); (RELEASE ALL RESOURCES-- called inside process_exit())
  
  // TODO: now iterate over each element in open_file and call close(e->fd)
  if (current->parent_process != NULL){
    struct thread * parent= current->parent_process;
    if(parent->waiting_on_which==current->tid){
      parent->child_status_after_wakeup=status;
      sema_up(&parent->wait_child);
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
