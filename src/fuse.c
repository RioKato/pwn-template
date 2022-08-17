#include "kutil.h"
#include <pthread.h>
#include <signal.h>

int counter = 0;
int fuse_read(const char *path, char *file_buf, size_t size, off_t offset,
              struct fuse_file_info *file_info) {
  switch (counter++) {
  default:
    break;
  }
}

void *run(void *arg) {
  lock_cpu();
  fuse_run(NULL, fuse_read);
}

int main(void) {
  lock_cpu();

  pthread_t thread;
  int err = pthread_create(&thread, NULL, run, NULL);
  sleep(1);

  int fd = -1;
  void *page = fuse_remmap_page(NULL, &fd);

  if (pthread_kill(thread, SIGTERM) == -1) {
    ABORT("pthread_kill");
  }
  pthread_exit(0);
}
