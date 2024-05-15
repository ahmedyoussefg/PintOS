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
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
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
  thread_exit ();
}

// OUR syscalls implementation:
/* Execute */
void execute_wrapper(struct intr_frame *f){
  char ** ptr=(char**)f->esp+1;
  validate_void_ptr(ptr);
  char *file_name = (char *) *ptr;
  f->eax=execute(file_name);   
}

pid_t execute(char *file_name){
  return process_execute(file_name);
}

/*=============================================================================*/

/* SYSCALLS IMPLEMENTATION: */

/*WAIT*/
/* Waits for a child process pid and retrieves the child's exit status. */
void wait_wrapper (struct intr_frame *f) {
  pid_t * ptr=(pid_t*)f->esp+1;
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
  
  process_exit();

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
  char **ptr_filename=((char **)f->esp+1);
  validate_void_ptr(ptr_filename);
  char *file_name=(char *)*ptr_filename;
  int *ptr_initial_size=((int *)f->esp+2);
  validate_void_ptr(ptr_initial_size);
  int initial_size= *ptr_initial_size;
  f->eax=create(file_name, initial_size);
}

bool create(const char *file,unsigned initial_size){
    /*try to create the file*/
    /*Error cases=>
    *1.)file name is wrong 
    *2.)file already exists
    *3.)internal memory allocation fails
    */
  if(!validate_file_name(file)){
    return false;
  }
  return filesys_create(file, initial_size);
}

/*=============================================================================*/

/*Remove a file*/
/*
*Deletes the file called file.
*Returns true if successful, false otherwise.
*/
void remove_wrapper(struct intr_frame *f){
  char **ptr_file_name=((char **)f->esp+1);
  validate_void_ptr(ptr_file_name);
  char *file_name=(char *)*ptr_file_name;
  f->eax=remove(file_name);  
}

bool remove(const char *file){
  if(!validate_file_name(file)){
    return false;
  }
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
  char *ptr_file_name=((char **)f->esp+1);
  validate_void_ptr(ptr_file_name);
  char *file_name=(char *)*ptr_file_name;
  f->eax=open(file_name);
}

int open(const char *file){
  if(!validate_file_name(file)){
    return -1;
  }
  static unsigned long current_fd=2;//standard to file, 0=>stdin, 1=>stdout
  lock_acquire(&files_sync_lock);
  struct file *opened_file=filesys_open(file);
  lock_release(&files_sync_lock);
  if(opened_file==NULL){
    return -1;
  }
  struct open_file *thread_files=(struct open_file *)malloc(sizeof(struct open_file));
  thread_files->file=opened_file;
  int temp_fd=current_fd;
  thread_files->fd=current_fd;
  current_fd++;
  list_push_back(&thread_current()->open_files,&thread_files->elem);
  return temp_fd;
}

/*=============================================================================*/

/*FILE SIZE*/
/*Returns the size, in bytes, of the file open as fd.*/
void filesize_wrapper(struct intr_frame *f){
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;
  f->eax=size(fd);
}

int size(int fd){
  struct file *file = get_file(fd);
  if(file==NULL){
    return -1;
  }
  return file_length(file);
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
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;

  //make pointer to buffer
  void *ptr_buffer=(void *)*((int *)f->esp+2);
  validate_void_ptr(ptr_buffer);
  void *buffer = (void *)ptr_buffer;
  unsigned *ptr_size = ((int *)f->esp+3);
  validate_void_ptr(ptr_size);
  unsigned size=(unsigned) *ptr_size;
  f->eax=read(fd, buffer, size);
}

int read(int fd,void * buffer, unsigned size){
  /*Read cases according to the file descriptor
  * fd=0=>read from the keyboard (stdin)
  * fd=1=>write to the console   (stdout)
  * fd>1=>read from the file     (file)
  */
  if(fd==0){
    for(int i=0;i<size;i++){
      lock_acquire(&files_sync_lock);
      ((char *)buffer)[i]=input_getc();
      lock_release(&files_sync_lock);
    }
    return size;
  } 
  else if(fd==1){
    //Negative area 
    return -1;
  }
  else{
    //Get the file from fd by searching in the open_files list of the current thread
    struct file *file = get_file(fd);
    if(file==NULL){
      return -1;
    }
    lock_acquire(&files_sync_lock);
    int bytes_read=file_read(file,buffer,size);
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
  
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;

  
  void *ptr_buffer=(void *)*((int *)f->esp+2);
  validate_void_ptr(ptr_buffer);
  void *buffer=(void *)*ptr_buffer;

  unsigned *ptr_size = ((int *)f->esp+3);
  validate_void_ptr(ptr_size);
  unsigned size=(unsigned) *ptr_size;
  
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
     putbuf(buffer,size);
     number_of_bytes_written=size;  
  }
  else{
    struct file *file = get_file(fd);
    if(file==NULL){
      return 0;
    }
    struct thread *current=thread_current();
    lock_acquire(&files_sync_lock);
    number_of_bytes_written=file_write(file,buffer,size);
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
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;

  unsigned *ptr_position = ((int *)f->esp+2);
  validate_void_ptr(ptr_position);
  unsigned position=(unsigned) *ptr_position;

  seek(fd,position);
}
void seek(int fd,unsigned position){
  struct file *seeked_file=get_file(fd);
  if(seeked_file==NULL){
    return;
  }
  lock_acquire(&files_sync_lock);
  file_seek(seeked_file,position);
  lock_release(&files_sync_lock);
}

/*=============================================================================*/

/*TELL*/
/*Returns the position of the next byte to be read or written in 
open file fd, expressed in bytes from the beginning of the file.*/

void tell_wrapper(struct intr_frame *f){
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;
  f->eax=tell(fd);
}

unsigned tell(int fd){
  struct file *file=get_file(fd);
  if(file==NULL){
    return INVALID_POSITION;
  }
  return file_tell(file);
}

/*=============================================================================*/

/*CLOSE*/
/*
*Closes file descriptor fd.
*Exiting or terminating a process implicitly closes all its open file descriptors,
*as if by calling this function for each one.
*/
void close_wrapper(struct intr_frame *f){
  int *ptr_fd=((int *)f->esp+1);
  validate_void_ptr(ptr_fd);
  int fd=*ptr_fd;
  close(fd);
}
void close(int fd){
  struct file *file=get_file(fd);
  if(file==NULL){
    return;
  }
  file_close(file);
}

/*=============================================================================*/

/*HELPER FUNCTIONS*/

/*GET FILE FROM THE FILE DESCRIPTOR*/
struct file *get_file(int fd){

  struct thread* current_thread=thread_current();
  struct list_elem *e;
  for(e=list_begin(&current_thread->open_files);
      e!=list_end(&current_thread->open_files);
      e=list_next(e)){
      struct open_file *opened_file=list_entry(e,struct open_file,elem);
      if(opened_file->fd==fd){
        return opened_file->file;
      }
  }
  return NULL;
}

/*VALID FILE NAME*/
/*CHECK IF THE FILE NAME IS VALID*/
bool validate_file_name(const char *file){
  if(file==NULL) return false;
  
  char bad_chars[] = "!%@^*~|";
  bool invalid_character_found=false;
  for(int i=0;i<strlen(bad_chars);i++){
    if(strchr(file,bad_chars[i])!=NULL){
      invalid_character_found=true;
      break;
    }
  }
  return !invalid_character_found;
}

/*VALID VOID POINTER*/
void validate_void_ptr(void *ptr){
  uint32_t * check =lookup_page(thread_current()->pagedir, ptr, false);
  if (ptr == NULL && !is_user_vaddr(ptr) && check == NULL ){
    exit(-1); // error
  }
}