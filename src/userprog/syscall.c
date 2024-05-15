#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/synch.h"

#define INVALID_POSITION -1
#include "threads/vaddr.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);
static struct lock files_sync_lock;


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
  int *sys_call_type= (int *)f->esp;//stack pointer

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
    case SYS_EXEC:
      // handle exec
      execute_wrapper(f);
      break;
    case SYS_CREATE:
      char *file_name=(char *)*((int *)f->esp+1);
      int initial_size= (int) *((int *)f->esp+2);
      bool file_create_success = create_wrapper(file_name, initial_size);
      break;
    case SYS_REMOVE:
      char *file_name=(char *)*((int *)f->esp+1);
      bool file_remove_success = remove_wrapper(file_name);
      break;
    case SYS_OPEN:
      char *file_name=(char *)*((int *)f->esp+1);
      int fd = open_wrapper(file_name);
      break;
    case SYS_FILESIZE:
      int fd = (int) *(sys_call_type+1);
      int file_size = filesize_wrapper(fd);
      break;
    case SYS_READ:
      int fd = (int) *(sys_call_type+1);
      void *buffer = (void *) *(sys_call_type+2);
      unsigned size = (unsigned) *(sys_call_type+3);
      int read_bytes=read_wrapper(fd,buffer,size);
      break;
    case SYS_WRITE:
      int fd = (int) *(sys_call_type+1);
      void *buffer=(void *) *(sys_call_type+2);
      unsigned size=(unsigned) *(sys_call_type+3);
      int written_bytes=write_wrapper(fd,buffer,size);
      break;
    case SYS_SEEK:
      int fd = (int) *(sys_call_type+1);
      unsigned position = (unsigned) *(sys_call_type+2);
      seek_wrapper(fd,position);
      break;
    case SYS_TELL:
      int fd = (int) *(sys_call_type+1);
      unsigned position = tell_wrapper(fd);
      break;
    case SYS_CLOSE:
      int fd = (int) *(sys_call_type+1);
      close_wrapper(fd);
      break;
  }
  //  TODO: ....continue rest of cases........ for remaining  syscalls
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
int create_wrapper(const char *file, unsigned initial_size){
  return create(file, initial_size);
}

bool create(const char *file,unsigned initial_size){
    /*try to create the file*/
    /*Error cases=>file name is wrong && 
    file already exists && internal memory allocation fails*/
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
int remove_wrapper(const char *file){
  return remove(file);
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
int open_wrapper(const char *file){
  if(!validate_file_name(file)){
    return -1;
  }
  return open(file);
}

int open(const char *file){
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
int filesize_wrapper(int fd){
  return size(fd);
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
int read_wrapper(int fd, void *buffer, unsigned size){
  return read(fd, buffer, size);
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
    return size;
  }       
}

/*=============================================================================*/

/*WRITE*/
/*
Writes size bytes from buffer to the open file fd. 
Returns the number of bytes actually written,
which may be less than size if some bytes could not be written.
*/
int write_wrapper(int fd, const void *buffer, unsigned size){
  return write(fd, buffer, size);
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
void seek_wrapper(int fd,unsigned position){
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

unsigned tell_wrapper(int fd){
  return tell(fd); 
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
void close_wrapper(int fd){
  return close(fd);
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
/*Function is used to check if the file name is valid or not*/
bool validate_file_name(char *file){
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
