#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

struct lock filesys_lock;
static void syscall_handler(struct intr_frame*);
struct lock filesys_lock;
void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); lock_init(&filesys_lock); }

/* 检查单个地址是否合法：
   1. 不为 NULL
   2. 是用户空间地址
   3. 在页表中已映射 */
bool is_valid_pointer(const void* ptr) {
    struct thread* curr = thread_current();
    if (ptr != NULL && is_user_vaddr(ptr) && 
        pagedir_get_page(curr->pcb->pagedir, ptr) != NULL) {
        return true;
    }
    return false;
}

/* 检查缓冲区是否连续合法 */
void check_buffer(const void* buffer, unsigned size) {
    char* ptr = (char*)buffer;
    for (unsigned i = 0; i < size; i++) {
        if (!is_valid_pointer(ptr + i)) {
            check_fail(); // 只要有一个字节非法，就退出
        }
    }
}

/* 检查字符串是否合法（用于 open, exec, remove, create） */
void check_string(const char* str) {
    if (!is_valid_pointer(str)) check_fail();
    // 还需要检查字符串结尾 '\0' 是否在合法内存中，防止无限读取
    // 这里简化处理，严谨的实现需要逐字符检查直到 '\0'
    while (is_valid_pointer(str)) {
        if (*str == '\0') return;
        str++;
    }
    check_fail(); // 没遇到 \0 就内存越界了
}


void check_fail(){
    int status = -1;
    struct thread* t = thread_current();
    /* 注意：pcb 和 process_name 需确保在你定义的结构体中存在 */
    printf("%s: exit(%d)\n", t->pcb->process_name, status); 
    t->info->exit_status = status;
    process_exit();
}

/* 从栈上读取参数，同时验证栈指针并没有越界 */
void get_args(struct intr_frame* f, int* args, int num_args) {
    int* ptr;
    for (int i = 0; i < num_args; i++) {
        ptr = (int*)f->esp + i + 1; // +1 是因为 args[0] 是系统调用号，参数从 esp+4 开始
        if (!is_valid_pointer((const void*)ptr)||!is_valid_pointer((char*)ptr + 3)) {
            check_fail();
        }
        args[i] = *ptr;
    }
}


static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  uint32_t argv[3];
  bool success = is_valid_pointer((const void*)args)&&is_valid_pointer((char*)args + 3);
  if (!success) {
    check_fail();
    return; // 如果指针无效，直接返回
  }
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */


  switch (args[0]) {
      case SYS_HALT:
          shutdown_power_off();
          break;

      case SYS_EXIT: {
          get_args(f, argv, 1);
          int status = argv[0];
          struct thread* t = thread_current();
          /* 注意：pcb 和 process_name 需确保在你定义的结构体中存在 */
          printf("%s: exit(%d)\n", t->pcb->process_name, status); 
          t->info->exit_status = status;
          process_exit();
          break; 
      }

      case SYS_PRACTICE:
          get_args(f, argv, 1);
          f->eax = argv[0] + 1;
          break;

      case SYS_EXEC:
          get_args(f, argv, 1);
          check_string((const char*)argv[0]);

          
          f->eax = process_execute((const char*)argv[0]);
          break;

      case SYS_WAIT:
          get_args(f, argv, 1);
          f->eax = process_wait((pid_t)argv[0]);
          break;

      case SYS_FORK:
          f->eax = process_fork(thread_current()->name, f);
          break;

      case SYS_CREATE: {
          get_args(f, argv, 2);
          char *file_name = (char *)argv[0];
          unsigned initial_size = (unsigned)argv[1];

          check_string(file_name); 
          if (file_name == NULL) {
              f->eax=-1;
              break;
          }

          lock_acquire(&filesys_lock);
          bool success = filesys_create(file_name, initial_size);
          lock_release(&filesys_lock);

          f->eax = success;
          break;
      }

      case SYS_REMOVE:{
          get_args(f, argv, 1);
          char *file_name = (char *)argv[0];
          check_string(file_name); 
          if (file_name == NULL) {
              f->eax=-1;
              break;
          }

          lock_acquire(&filesys_lock);
          bool success = filesys_remove(file_name);
          lock_release(&filesys_lock);

          f->eax = success;
          break;
      }

      case SYS_OPEN:{
          get_args(f, argv, 1);
          char *file_name = (char *)argv[0];
          check_string(file_name);
          if (file_name == NULL) {
              f->eax=-1;
              break;
          }

          lock_acquire(&filesys_lock);
          struct file* fptr = filesys_open(file_name);
          lock_release(&filesys_lock);

          if (fptr == NULL) {
              f->eax = -1; // 打开失败
          } else {
              // 将文件指针存储到当前线程的文件描述符表中
              struct thread* curr = thread_current();
              int fd = add_fd_to_table(curr, fptr); // 你需要实现这个函数
              f->eax = fd;
          }
          break;
      }

      case SYS_FILESIZE:{
          get_args(f, argv, 1);
          int fd = (int)argv[0];
          struct thread* curr = thread_current();
          if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
              f->eax = -1; // 无效的文件描述符
              break;
          }

          lock_acquire(&filesys_lock);
          int size = file_length(curr->pcb->fd_table[fd]);
          lock_release(&filesys_lock);

          f->eax = (int)size;
          break;
      }

      case SYS_READ:{
          get_args(f, argv, 3);
          int fd = (int)argv[0];
          void* buffer = (void*)argv[1];
          unsigned size = (unsigned)argv[2];

          check_buffer(buffer, size);
          if (buffer == NULL) {
              f->eax = -1; // 建议使用 thread_exit() 或统一的退出逻辑
              break;
          }

          if (fd == 0) { 
                  /* 特殊处理：标准输入 (STDIN) */
                  // 从键盘读取数据，使用 input_getc() 逐个字符读取
                  for (unsigned i = 0; i < size; i++) {
                      ((char*)buffer)[i] = input_getc();
                  }
                  f->eax = size; // 读取了多少就返回多少
          } 
          else if (fd == 1 || fd == 2) {
              /* 错误处理：标准输出 (STDOUT) 不能读取 */
              f->eax = 0; 
          }
          else {
              /* 普通文件处理 */
              struct thread* curr = thread_current();
              if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
                  f->eax = -1;
                  break;
              }

              lock_acquire(&filesys_lock);
              // file_read 内部会更新文件的 offset，所以不需要你手动去移动位置
              f->eax = file_read(curr->pcb->fd_table[fd], buffer, size);
              lock_release(&filesys_lock);
          }
          break;
      }
      case SYS_WRITE:{
          
          get_args(f, argv, 3);
          int fd = (int)argv[0];
          const void* buffer = (const void*)argv[1];
          unsigned size = (unsigned)argv[2];
          check_buffer(buffer, size);
          if (buffer == NULL) {
              f->eax = -1; // 建议使用 thread_exit() 或统一的退出逻辑
              break;
          }
          if (fd == 1) { 
                  /* 特殊处理：标准输出 (STDOUT) */
                  // 使用 lib/kernel/console.h 中的 putbuf 一次性打印整个缓冲区
                  putbuf(buffer, size);
                  f->eax = size; // 写入了多少就返回多少
          } 
          else if (fd == 0|| fd == 2) {
              /* 错误处理：标准输入 (STDIN) 不能写入 */
              f->eax = 0; 
          }
          else {
              /* 普通文件处理 */
              struct thread* curr = thread_current();
              if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
                  f->eax = -1;
                  break;
              }

              lock_acquire(&filesys_lock);
              // file_write 内部会更新文件的 offset，所以不需要你手动去移动位置
              f->eax = file_write(curr->pcb->fd_table[fd], buffer, size);
              lock_release(&filesys_lock);
          }
          break;
      }

      case SYS_SEEK:{
          get_args(f, argv, 2);
          int fd = (int)argv[0];
          unsigned position = (unsigned)argv[1];

          struct thread* curr = thread_current();
          if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
              break; // 无效的文件描述符，直接返回
          }

          lock_acquire(&filesys_lock);
          file_seek(curr->pcb->fd_table[fd], position);
          lock_release(&filesys_lock);

          break;
      }

      case SYS_TELL:{
          get_args(f, argv, 1);
          int fd = (int)argv[0];

          struct thread* curr = thread_current();
          if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
              f->eax = -1; // 无效的文件描述符
              break;
          }

          lock_acquire(&filesys_lock);
          unsigned position = file_tell(curr->pcb->fd_table[fd]);
          lock_release(&filesys_lock);

          f->eax = position;
          break;
      }

      case SYS_CLOSE:{
          get_args(f, argv, 1);
          int fd = (int)argv[0];

          struct thread* curr = thread_current();
          if (fd < 0 || fd >= 128 || curr->pcb->fd_table[fd] == NULL) {
              break; // 无效的文件描述符，直接返回
          }

          lock_acquire(&filesys_lock);
          file_close(curr->pcb->fd_table[fd]);
          curr->pcb->fd_table[fd] = NULL; // 从文件描述符表中移除
          lock_release(&filesys_lock);

          break;
      }

      default:
          /* 处理未知的系统调用，通常应该杀掉进程 */
          printf("Unknown system call: %d\n", args[0]);
          thread_exit();
          break;
  }
}
