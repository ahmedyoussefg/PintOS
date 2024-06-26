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
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "lib/kernel/list.h"
#include "lib/user/syscall.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "string.h"
#include "stdlib.h"

#define INVALID_POSITION -1


static void syscall_handler (struct intr_frame *);
static struct lock files_sync_lock;



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_sync_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{

  validate_void_ptr(f->esp);  
  int *sys_call_type= (int *)f->esp;//stack pointer

  /* Inside each syscall wrapper : call validate_void_ptr: check if ptr not null, 
   * check if user vaddr , ptr correctly mapped to virtual address*/
  switch (*sys_call_type){
    case SYS_WAIT:
      wait_wrapper(f);
      break;
    case SYS_EXIT:
      exit_wrapper(f);
      break;
    case SYS_EXEC:
      execute_wrapper(f);
      break;
    case SYS_HALT:
      halt_wrapper();
      break;
    case SYS_CREATE:
      create_wrapper(f);
      break;
    case SYS_REMOVE:
      remove_wrapper(f);
      break;
    case SYS_OPEN:
      open_wrapper(f);
      break;
    case SYS_FILESIZE:
      filesize_wrapper(f);
      break;
    case SYS_READ:
      read_wrapper(f);
      break;
    case SYS_WRITE:
      write_wrapper(f);
      break;
    case SYS_SEEK:
      seek_wrapper(f);
      break;
    case SYS_TELL:
      tell_wrapper(f);
      break;
    case SYS_CLOSE:
      close_wrapper(f);
      break;
  }
}

// OUR syscalls implementation:
/* Execute */
/* Function that serves as a wrapper to execute a program. It is designed to be called
   within an operating system kernel to manage program execution from system calls. */
void execute_wrapper(struct intr_frame *f){
  /* Retrieve the pointer to the first argument after the return address on the stack.
     The interrupt frame's stack pointer ('esp') points to the return address. Incrementing
     it by 1 accesses the next element on the stack, which is the first argument. */
  int *ptr = (int *)f->esp + 1;

  /* Validate the pointer to ensure it points to a valid memory location before dereferencing.
     This is crucial to prevent the kernel from crashing due to invalid memory accesses. */
  validate_void_ptr(ptr);

  /* Dereference the pointer to obtain the file name intended for execution. The pointer
     is cast to a 'char *' because system calls related to file operations typically
     expect string arguments. */
  char *file_name = (char *) *ptr;

  /* Call the 'execute' function with the file name. The 'execute' function is expected
     to handle the actual process creation and execution. The return value of 'execute'
     is typically the process ID (PID) of the newly created process, or an error code if
     the execution fails. This return value is stored in the 'eax' register of the
     interrupt frame to pass it back to the caller, adhering to the system calling convention. */
  f->eax = execute(file_name); 
}


pid_t execute(char *file_name){
  return process_execute(file_name);
}

/*=============================================================================*/

/* SYSCALLS IMPLEMENTATION: */

/*WAIT*/
/* Waits for a child process pid and retrieves the child's exit status. */
void wait_wrapper (struct intr_frame *f) {
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  pid_t pid = (pid_t) *ptr;
  f->eax=wait(pid);   // return value
}

int wait(pid_t tid){
  return process_wait((pid_t) tid); 
}

/*=============================================================================*/

/* Halt */
void halt_wrapper(void)
{
  halt();
}

void halt(void){
  // handle halt
  shutdown_power_off();
}

/*=============================================================================*/

/* Exit */
void exit_wrapper(struct intr_frame *f) {
  int *ptr=(int *)f->esp+1;
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
  printf("%s: exit(%d)\n", current->filename, status);

  // process_exit();

  // TODO: now iterate over each element in open_file and call close(e->fd)

  // if the parent is waiting for thread, give the parent the status of child exit
  if (current->parent_process != NULL){
    struct thread * parent= current->parent_process;
    if(parent->waiting_on_which==current->tid){
      parent->child_status_after_wakeup=status;
    }
  }
  // call exit_thread();
  thread_exit();  
}

/*=============================================================================*/

/*Create a file without openning it with an initial size*/
void create_wrapper(struct intr_frame *f){
  int *ptr1=(int *)f->esp+1;
  validate_void_ptr(ptr1);
  char *file_name=(char *)*ptr1;
  validate_void_ptr(file_name);
  int *ptr2=(int *)f->esp + 2;
  validate_void_ptr(ptr2);
  unsigned initial_size= (unsigned) *ptr2;
  f->eax=create(file_name, initial_size);
}

bool create(const char *file,unsigned initial_size){
    /*try to create the file*/
    /*Error cases=>
    *1.)file already exists
    *2.)internal memory allocation fails
    */
  return filesys_create(file, initial_size);
}

/*=============================================================================*/

/*Remove a file*/
/*
*Deletes the file called file.
*Returns true if successful, false otherwise.
*/
void remove_wrapper(struct intr_frame *f){
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  char *file_name=(char *)*ptr;
  f->eax=remove(file_name);  
}

bool remove(const char *file){
  return filesys_remove(file); 
}

/*=============================================================================*/

/*OPEN*/
/*
*Opens the file called file.
*Returns a nonnegative integer handle called a "file descriptor" (fd),
*or -1 if the file could not be opened.
*/
void open_wrapper(struct intr_frame *f){
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  char *file_name=(char *)*ptr;
  validate_void_ptr(file_name);
  f->eax=open(file_name);
}

int open(const char *file){
  static unsigned long current_fd=2;//standard to file, 0=>stdin, 1=>stdout

  lock_acquire(&files_sync_lock);
  struct file *opened_file=filesys_open(file);
  lock_release(&files_sync_lock);
  if(opened_file==NULL){
    return -1;
  }

  struct open_file *file_to_open=(struct open_file *)malloc(sizeof(struct open_file));

  file_to_open->file=opened_file;
  file_to_open->fd=current_fd;
  struct list_elem *element=&file_to_open->elem;
  list_push_back(&thread_current()->open_files,element);

  lock_acquire(&files_sync_lock);
  current_fd++;
  lock_release(&files_sync_lock);

  return file_to_open->fd;
}

/*=============================================================================*/

/*FILE SIZE*/
/*Returns the size, in bytes, of the file open as fd.*/
void filesize_wrapper(struct intr_frame *f){
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  int fd=*ptr;
  f->eax=size(fd);
}

int size(int fd){
  struct open_file *file = get_file(fd);
  if(file==NULL){
    return -1;
  }
  return file_length(file->file);
}

/*=============================================================================*/

/*READ*/
/*
*Reads size bytes from the file open as fd into buffer. 
*Returns the number of bytes actually read (0 at end of file),
*or -1 if the file could not be read (due to a condition other than end of file).
*Fd 0 reads from the keyboard using input_getc().
*/
void read_wrapper(struct intr_frame *f){
  int *ptr1=(int *)f->esp+1;
  validate_void_ptr(ptr1);
  int fd=(int)*ptr1;

  //make pointer to buffer
  int *ptr2=(int *)f->esp+2;
  validate_void_ptr(ptr2);
  void *buffer = (void *) *ptr2;
  validate_void_ptr(buffer);
  int *ptr3=(int *)f->esp+3;
  validate_void_ptr(ptr3);
  unsigned size=(unsigned) *ptr3;
  f->eax=read(fd, buffer, size);
}

int read(int fd,void * buffer, unsigned size){
  /*Read cases according to the file descriptor
  * fd=0=>read from the keyboard (stdin)
  * fd=1=>write to the console   (stdout)
  * fd>1=>read from the file     (file)
  */
  if(fd==0){
    for(unsigned int i=0;i<size;i++){
      lock_acquire(&files_sync_lock);
      char c=input_getc();
      lock_release(&files_sync_lock);
      buffer+=c;
    }
    return size;
  } 
  else {
    //Get the file from fd by searching in the open_files list of the current thread
    struct open_file *file = get_file(fd);
    if(file==NULL){
      return -1;
    }
    lock_acquire(&files_sync_lock);
    int bytes_read=file_read(file->file,buffer,size);
    lock_release(&files_sync_lock);
    return bytes_read;
  }       
}

/*=============================================================================*/

/*WRITE*/
/*
*Writes size bytes from buffer to the open file fd. 
*Returns the number of bytes actually written,
*which may be less than size if some bytes could not be written.
*/
void write_wrapper(struct intr_frame *f){
  
  int *ptr1=(int *)f->esp+1;
  validate_void_ptr(ptr1);
  int fd=(int)*ptr1;
  if(fd==0) {
    exit(-1);
    return;
  }
  int *ptr2=(int *)f->esp+2;
  validate_void_ptr(ptr2);
  void *buffer=(void *)*ptr2;
  validate_void_ptr(buffer);
  int *ptr3=(int *)f->esp+3;
  validate_void_ptr(ptr3);
  unsigned size=(unsigned) *ptr3;
  
  f->eax=write(fd, buffer, size);
}

int write(int fd, const void *buffer, unsigned size){
  int number_of_bytes_written=0;
  /*
  Fd 1 writes to the console. Your code to write to the console 
  should write all of buffer in one call to putbuf(), at least as long as
  size is not bigger than a few hundred bytes.
  (It is reasonable to break up larger buffers.) 
  Otherwise, lines of text output by different processes may end 
  up interleaved on the console, confusing both human readers and our grading scripts.
  */
  if(fd==1){
    lock_acquire(&files_sync_lock);
     putbuf(buffer,size);
    lock_release(&files_sync_lock);

     number_of_bytes_written=size;  
  }
  else{
    struct open_file *file = get_file(fd);
    if(file==NULL){
      return -1;
    }
    // struct thread *current=thread_current();
    lock_acquire(&files_sync_lock);
    number_of_bytes_written=file_write(file->file,buffer,size);
    lock_release(&files_sync_lock);
  }
  return number_of_bytes_written;
}

/*=============================================================================*/

/*SEEK*/
/*
*Changes the next byte to be read or written in open file fd to position, expressed in bytes
*from the beginning of the file.
*(Thus, a position of 0 is the file's start.)
*/
void seek_wrapper(struct intr_frame *f){
  int *ptr1=(int *)f->esp+1;
  validate_void_ptr(ptr1);
  int fd=(int) *ptr1;

  int *ptr2=(int *)f->esp+2;
  validate_void_ptr(ptr2);
  unsigned position=(unsigned) *ptr2;

  seek(fd,position);
}
void seek(int fd,unsigned position){
  struct open_file *seeked_file=get_file(fd);
  if(seeked_file==NULL){
    return;
  }
  lock_acquire(&files_sync_lock);
  file_seek(seeked_file->file,position);
  lock_release(&files_sync_lock);
}

/*=============================================================================*/

/*TELL*/
/*Returns the position of the next byte to be read or written in 
open file fd, expressed in bytes from the beginning of the file.*/

void tell_wrapper(struct intr_frame *f){
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  int fd=*ptr;
  f->eax=tell(fd);
}

unsigned tell(int fd){
  struct open_file *file=get_file(fd);
  if(file==NULL){
    return INVALID_POSITION;
  }
  return file_tell(file->file);
}

/*=============================================================================*/

/*CLOSE*/
/*
*Closes file descriptor fd.
*Exiting or terminating a process implicitly closes all its open file descriptors,
*as if by calling this function for each one.
*/
void close_wrapper(struct intr_frame *f){
  int *ptr=(int *)f->esp+1;
  validate_void_ptr(ptr);
  int fd=*ptr;
  close(fd);
}
void close(int fd){
  struct open_file *file=get_file(fd);
  if(file==NULL){
    exit(-1);
    return;
  }
  list_remove(&file->elem);
  lock_acquire(&files_sync_lock);
  file_close(file->file);
  lock_release(&files_sync_lock);
}

/*=============================================================================*/

/*HELPER FUNCTIONS*/

/*GET FILE FROM THE FILE DESCRIPTOR*/
struct open_file *get_file(int fd){

  struct thread* current_thread=thread_current();
  struct list_elem *e;
  for(e=list_begin(&current_thread->open_files);
      e!=list_end(&current_thread->open_files);
      e=list_next(e)){
      struct open_file *opened_file=list_entry(e,struct open_file,elem);
      if(opened_file->fd==fd){
        return opened_file;
      }
  }
  return NULL;
}


/*VALID VOID POINTER*/
void validate_void_ptr(void *ptr){
  if (ptr == NULL || !is_user_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL ){
    exit(-1); // error
  }
}