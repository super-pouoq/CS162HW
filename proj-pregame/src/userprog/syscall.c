#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    int status = args[1];
    struct thread* t = thread_current();
    printf("%s: exit(%d)\n", t->pcb->process_name, status);
    t->info->exit_status = status;
    process_exit();
  }
  if(args[0] == SYS_HALT) {
    shutdown_power_off();
  }
  if(args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
  if(args[0] == SYS_EXEC) {
    f->eax = process_execute((const char*)args[1]);
  }
  if(args[0] == SYS_WAIT) {
    f->eax = process_wait((pid_t)args[1]);
  }
  if(args[0] == SYS_FORK) {
    f->eax = process_fork(thread_current()->name, f);
  }
}
