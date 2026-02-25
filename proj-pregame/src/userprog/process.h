#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "lib/kernel/hash.h"
// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;
struct intr_frame;
/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
   /* Owned by process.c. */
   uint32_t* pagedir;          /* Page directory. */
   char process_name[16];      /* Name of the main thread */
   struct thread* main_thread; /* Pointer to main thread */
   
   struct file* fd_table[128]; /* 文件描述符表 */
   struct lock fd_lock; /* 保护文件描述符表的锁 */
   struct hash user_locks_map;     /* Hash table: key=user_ptr, value=kernel_lock_struct */
   struct hash user_semas_map;     /* Hash table: key=user_ptr, value=kernel_sema_struct */
   struct lock sync_map_lock;      /* 保护上述 hash 表的锁 */
};

/* 内核中代表一个用户级锁的结构 */
struct kernel_user_lock {
  struct hash_elem elem;      /* 用于放入 hash 表 */
  char* user_addr;          /* 用户空间的锁地址 (作为 Key) */
  struct lock internal_lock;  /* 内核实际用来阻塞线程的锁 */
};

/* 内核中代表一个用户级信号量的结构 */
struct kernel_user_sema {
  struct hash_elem elem;
  char* user_addr;          /* 用户空间的信号量地址 (作为 Key) */                 /* 信号量计数值 */
  struct semaphore internal_sema; /* 内核实际用来阻塞线程的信号量 */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

pid_t process_fork(const char* name, struct intr_frame* iframe);
static void start_child_process(void*);
static bool pagedir_duplicate(struct thread *parent, struct thread *child);
bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);
#endif /* userprog/process.h */
