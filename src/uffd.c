#include "kutil.c"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* open */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
/* syscall */
#include <sys/syscall.h>
/* userfaultfd */
#include <linux/userfaultfd.h>
#include <sys/types.h>
/* pthread */
#include <pthread.h>
/* mmap */
#include <sys/mman.h>
/* ioctl */
#include <sys/ioctl.h>
/* poll */
#include <poll.h>

static void *uffd_handler(void *arg) {
  long uffd = *(int *)arg;

  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    ABORT("mmap");

  int count;
  for (count = 0; 1; count++) {
    struct pollfd pollfd;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    int nready = poll(&pollfd, 1, -1);
    if (nready == -1)
      ABORT("poll");

    struct uffd_msg uffd_msg;
    ssize_t nread = read(uffd, &uffd_msg, sizeof(uffd_msg));
    if (nread == 0) {
      fprintf(stderr, "EOF on userfaultfd!\n");
      exit(EXIT_FAILURE);
    }

    if (nread == -1)
      ABORT("read");

    if (uffd_msg.event != UFFD_EVENT_PAGEFAULT) {
      fprintf(stderr, "Unexpected event on userfaultfd\n");
      exit(EXIT_FAILURE);
    }

    switch (count) {
    default: {
    }
    }

    struct uffdio_copy uffdio_copy;
    uffdio_copy.src = (unsigned long)page;
    uffdio_copy.dst =
        (unsigned long)uffd_msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uffdio_copy.len = PAGE_SIZE;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
      ABORT("ioctl-UFFDIO_COPY");
  }
}

void uffd_run(void *addr, uint64_t len) {
  int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1)
    ABORT("userfaultfd");

  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    ABORT("ioctl-UFFDIO_API");

  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (unsigned long)addr,
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    ABORT("ioctl-UFFDIO_REGISTER");

  pthread_t thread;
  int err = pthread_create(&thread, NULL, uffd_handler, (void *)&uffd);
  if (err != 0) {
    errno = err;
    ABORT("pthread_create");
  }
}

int main() {
  void *addr = mmap((void *)0x77770000, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr == MAP_FAILED)
    ABORT("mmap");

  uffd_run(addr, 0x1000);
}
