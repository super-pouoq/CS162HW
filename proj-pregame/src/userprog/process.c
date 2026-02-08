#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define MAX_ARG 32

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);
void load_args(const char* file_name, void** esp);
struct start_process_args {
    char *file_name;              // 本来要传的文件名
    struct child_info *info;      // 你想传的“中间人”结构体
};
struct start_child_process_args{
    struct intr_frame* parent_if;
    struct child_info* info;
    struct thread* parent_thread;
};

/*load args*/
void load_args(const char* file_name, void** esp) {
  char* tokens[MAX_ARG];
  uint32_t args_addr[64];
  int argc = 0;
  char* save_ptr;
  char* token;
  token = strtok_r((char*)file_name, " ", &save_ptr);

  while (token != NULL && argc < MAX_ARG) {
    tokens[argc] = token;
    argc++;
    token = strtok_r(NULL, " ", &save_ptr);
  }

  for(int i = argc - 1; i >= 0; i--) {
    int len = strlen(tokens[i]) + 1;
    *esp -= len;
    memcpy(*esp, tokens[i], len);
    args_addr[i] = (uint32_t)(*esp);
  }
  //word align
  int total_extra_size = (argc) * 4 + 4 + 4 + 4;
  // 1. 计算出所有参数占用的空间：(argc 个参数指针 + argv 指针 + argc + fake return address + \0的空间)

  /* 3. 实现 16 字节对齐 */
  // 预演一下压完所有东西后的位置，然后强行对齐
  uint32_t final_esp = (uint32_t)(*esp) - total_extra_size;
  uint32_t aligned_esp = final_esp & 0xfffffff0; 
  //aligned_esp <= final_esp 恒成立

  // 算出为了对齐需要额外补多少 0
  uint32_t padding = final_esp - aligned_esp; 
  if (padding > 0) {
      *esp -= padding;
      memset(*esp, 0, padding);
  }
  for(int i = argc; i >= 0; i--) {
    *esp -= 4;
    if(i == argc) {
      *(uint32_t*)(*esp) = 0;
    } else {
      *(uint32_t*)(*esp) = args_addr[i];
    }
  }
  uint32_t argv = (uint32_t)(*esp);
  *esp -= 4;
  *(uint32_t*)(*esp) = argv;
  *esp -= 4;
  *(uint32_t*)(*esp) = argc;
  *esp -= 4;
  *(uint32_t*)(*esp) = 0; //fake return address
}
/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  struct child_info* info = malloc(sizeof(struct child_info));
  if (info == NULL)
    return TID_ERROR;
  info->tid = TID_ERROR;
  info->is_exit = false;
  info->is_waited = false;
  info->exit_status = 0;
  sema_init(&info->wait_sema, 0);
  
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  char thread_name[16]; // 线程名最长就 16 字节，够用了
  strlcpy(thread_name, file_name, sizeof thread_name);
  char *cp = thread_name;
  while(*cp != '\0' && *cp != ' '){
    cp++;
  }
  char delimiter = *cp;
  *cp = '\0';

  list_push_back(&thread_current()->children, &info->elem);
  struct start_process_args *args = malloc(sizeof(struct start_process_args));
    args->file_name = fn_copy;
    args->info = info;
  
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(thread_name, PRI_DEFAULT, start_process, args);
  *cp = delimiter;
  if (tid == TID_ERROR){
    list_remove(&info->elem);
    palloc_free_page(fn_copy);
    free(args);
    free(info);
  }
  else{
    info->tid = tid;
  }
  return tid;
}

pid_t process_fork(const char* name, struct intr_frame* iframe) {
  struct child_info* info = malloc(sizeof(struct child_info));
  if (info == NULL)
    return TID_ERROR;
  info->tid = TID_ERROR;
  info->is_exit = false;
  info->is_waited = false;
  info->exit_status = 0;
  sema_init(&info->wait_sema, 0);
  char thread_name[16];
  strlcpy(thread_name, name, sizeof thread_name);
  char *cp = thread_name;
  while(*cp != '\0' && *cp != ' '){
    cp++;
  }
  char delimiter = *cp;
  *cp = '\0';
  list_push_back(&thread_current()->children, &info->elem);
  struct start_child_process_args *args = malloc(sizeof(struct start_child_process_args));
    args->parent_if = iframe;
    args->info = info;
    args->parent_thread = thread_current();
  tid_t tid = thread_create(thread_name, PRI_DEFAULT, start_child_process, args);
  *cp = delimiter;
  if (tid == TID_ERROR){
    list_remove(&info->elem);
    free(args);
    free(info);
  }
  else{
    info->tid = tid;
  }
  return tid;
}

static void start_child_process(void* args_) {
    struct start_child_process_args* args = (struct start_child_process_args*)args_;
    struct thread* curr = thread_current();
    struct intr_frame if_;

    // 1. 【接收记忆】深拷贝父进程的中断帧到我的本地变量
    // 因为 args->parent_if 是指针，这行执行完之前，父进程绝对不能动
    memcpy(&if_, args->parent_if, sizeof(struct intr_frame));
    
    // fork 的魔法：子进程返回 0
    if_.eax = 0; 
    curr->pcb->pagedir = pagedir_create();
    process_activate();
    // 2. 【克隆身体】复制页表、文件描述符等
    bool success = pagedir_duplicate(args->parent_thread, curr);
    
    // 3. 【填写身份证】
    if (success) {
        args->info->tid = curr->tid;
    } else {
        args->info->tid = TID_ERROR;
    }

    // 4. 【关键】通知父进程：我拷贝完了，你可以走了
    // 此时 args->parent_if 这个指针就没有利用价值了，父进程栈销毁也没事了
    sema_up(&args->info->wait_sema);

    // 5. 资源清理
    free(args); // args 是父进程 malloc 的，子进程用完了要负责释放

    if (!success) {
        thread_exit(); // 克隆失败，自杀
    }

    // 6. 带着父进程的记忆，跳入用户态
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED();
}

/* 把父进程的页表复制给子进程 
   成功返回 true，失败返回 false */
static bool pagedir_duplicate(struct thread *parent, struct thread *child) {
    uint32_t *parent_pd = parent->pcb->pagedir;
    uint32_t *child_pd = child->pcb->pagedir; // 这时应该是空的，或者是刚初始化的
    void *vaddr;

    // 我们遍历整个用户空间的虚拟地址 (从 0 到 PHYS_BASE)
    // 每次跳过一页 (PGSIZE = 4KB)
    for (vaddr = 0; vaddr < PHYS_BASE; vaddr += PGSIZE) {
        
        // 1. 问：父进程在这个虚拟地址有数据吗？
        void *parent_kpage = pagedir_get_page(parent_pd, vaddr);

        // 2. 如果父进程这里有页，我们也要有！
        if (parent_kpage != NULL) {
            // A. 给子进程申请一个新的物理页 (Kernel Page)
            void *child_kpage = palloc_get_page(PAL_USER | PAL_ZERO);
            if (child_kpage == NULL) {
                return false; // 内存不足，拷贝失败
            }

            // B. 【深拷贝】把父进程这一页的内容，原封不动地抄过来
            // 注意：一定要用 PGSIZE，不要用 strlen，因为里面可能包含 \0
            memcpy(child_kpage, parent_kpage, PGSIZE);

            // C. 建立映射：让子进程的 vaddr 指向这个新的 child_kpage
            // 我们还需要知道这页是不是只读的 (writable?)
            // 这个需要去 pagedir.c 里加个函数或者暂时默认为 true (Pintos Project 2 只有代码段是只读的)
            // 简单的做法是：假设都是可写的，或者自己去 pagedir.c 实现 lookup_page_writable
            bool writable = true; 
            
            // 将新页挂载到子进程的页表上
            if (!pagedir_set_page(child_pd, vaddr, child_kpage, writable)) {
                palloc_free_page(child_kpage);
                return false;
            }
        }
    }
    return true;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args_) {
  struct start_process_args *args = (struct start_process_args *)args_;
  char* file_name = args->file_name;
  struct child_info *info = args->info;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  t->info = info;
  free(args); // 释放传参结构体内容，避免内存泄漏
  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;
  //检查是否分配成功
  //将 PCB 连接到线程上
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    //保证在我们初始化 pagedir 之前不会被使用
    // 因为 timer_interrupt 可能随时打断我们
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  }

  //把文件名拆开，只留程序名部分
  char *cp = file_name;
  
  // 1. 手动找到第一个空格
  while (*cp != '\0' && *cp != ' ') {
      cp++;
  }
  
  char delimiter = *cp; // 记住原来的字符（可能是空格，也可能是 \0）
  *cp = '\0';           // 暂时切断
  //把elf加载到内存中
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    //success = load(file_name, &if_.eip, &if_.esp);
    success = load(file_name, &if_.eip, &if_.esp);
  }
  *cp = delimiter; // 恢复原来的字符
  // 2. 装载命令行参数到用户栈
  load_args(file_name, &if_.esp);

  //todo : prepare for argc and argv
  /* Handle failure with succesful PCB malloc. Must free the PCB */
  // 如果加载失败，但 PCB 分配成功了
  // 要把 PCB 给 free 掉，避免内存泄漏
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  // 无论成功与否，都要释放文件名页
  palloc_free_page(file_name);
  // 如果加载失败，就把 exit_status 设为 -1，通知父进程
  if (!success) {
    t->info->exit_status = -1;
    sema_up(&info->wait_sema); // 通知父进程 load 失败了
    t->info->is_exit = true;
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  /*启动用户进程通过模拟从中断返回来实现，由 intr_exit 实现（在 threads/intr-stubs.S 中）。
    因为 intr_exit 以 struct intr_frame 的形式在堆栈上获取它的所有参数，
    我们只需将堆栈指针（%esp）指向我们的堆栈帧并跳转到它。*/
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
    // 1. 获取当前线程（父进程）
    struct thread *cur = thread_current();
    
    // 2. 遍历 cur->children 链表，寻找 tid == child_pid 的那个 info
    struct list_elem *e;
    struct child_info *target_info = NULL;
    
    for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
        struct child_info *info = list_entry(e, struct child_info, elem);
        if (info->tid == child_pid) {
            target_info = info;
            break;
        }
    }

    // 3. 如果找不到（比如这是一个无效的 pid，或者是别人的孩子），直接返回 -1
    if (target_info == NULL) {
        return -1;
    }

    // 4. 【关键】如果这个孩子已经被 wait 过了，不能再 wait，返回 -1
    // (Pintos 文档要求：一个进程只能被父进程 wait 一次)
    if (target_info->is_waited) {
        return -1;
    }
    
    // 5. 标记为已等待
    target_info->is_waited = true;

    // 6. 等待子进程结束（P 操作）
    // 如果子进程还没结束，父进程会在这里阻塞（睡觉）
    // 如果子进程已经结束（exit_exit = true），信号量已经是 1 了，这里直接减为 0 并继续
    sema_down(&target_info->wait_sema);

    // 7. 醒来后，获取退出码
    int status = target_info->exit_status;

    // 8. 收尸（将 info 从链表移除并释放内存）
    list_remove(&target_info->elem);
    free(target_info);

    // 9. 返回退出码
    return status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* 1. 打印退出信息 (必做！否则测试全挂)
     格式必须严格按照 "%s: exit(%d)\n"
     如果 cur->info 为空（比如内核线程），这里可能会崩，可以加个判断 */
  int exit_code = 0;
  if (cur->info != NULL) {
      exit_code = cur->info->exit_status;
  }

  /* 2. 通知父进程：我做完了 */
  if (cur->info != NULL) {
      // 标记我已经退出了
      cur->info->is_exit = true;
      // 唤醒父进程（父进程正在 wait_sema 上睡觉）
      sema_up(&cur->info->wait_sema);
  }

  /* 3. 处理孤儿（我的孩子们）
     如果我死了，我的孩子们还在运行，或者它们死了还没被收尸，
     我作为父亲，临死前要把这本“花名册”销毁掉，防止内存泄漏。
     
     注意：这是一个简单的清理。更严谨的做法涉及“孤儿进程”的处理，
     但为了跑通测试，至少要把 malloc 的 list 节点释放掉。 */
  struct list_elem *e = list_begin(&cur->children);
  while (e != list_end(&cur->children)) {
      struct list_elem *next = list_next(e);
      struct child_info *child = list_entry(e, struct child_info, elem);
      
      // 这里的逻辑有点复杂：如果子进程还在跑，我能不能 free 它的 info？
      // 简单做法：把 info 从链表摘除，free 掉。
      // 但要小心子进程访问悬空指针（这是一个进阶的同步难题）。
      // 现阶段你可以先尝试释放，或者先只做 list_remove。
      list_remove(e);
      free(child); 
      
      e = next;
  }

  /* 下面是原本的内存清理逻辑，保持不变 */
  
  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory... */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  /* 4. 删掉旧的全局信号量操作 */
  // sema_up(&temporary); <--- 这行删掉！

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);


/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }


  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZRO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  char* tokens[MAX_ARG];
  uint32_t args_addr[64];
  int argc = 0;
  char* save_ptr;
  char* token;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
    {
        *esp = PHYS_BASE;
      }
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
