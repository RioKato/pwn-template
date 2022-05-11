#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MSG_COPY 040000
#define PAGE 0x1000
#define HDRLEN_MSG 0x30
#define HDRLEN_SEG 0x08
#define DATALEN_MSG (PAGE - HDRLEN_MSG)
#define DATALEN_SEG (PAGE - HDRLEN_SEG)

#define ABORT(msg)                                                             \
  do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

struct msgbuf {
  long mtype;
  char mtext[1];
};

void kmalloc_msg(int *msgid, size_t size) {
  assert(size <= PAGE && size >= HDRLEN_MSG);

  if (!msgid) {
    *msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (*msgid == -1) {
      ABORT("msgget");
    }
  }

  struct msgbuf *msgbuf =
      (struct msgbuf *)malloc(sizeof(long) + size - HDRLEN_MSG);
  if (!msgbuf) {
    ABORT("malloc");
  }
  msgbuf->mtype = 1;

  int err = msgsnd(*msgid, msgbuf, size - HDRLEN_MSG, 0);
  if (err == -1) {
    ABORT("msgsnd");
  }

  free(msgbuf);
}

void kmalloc_seg(int *msgid, size_t size) {
  assert(size <= PAGE && size >= HDRLEN_SEG);

  if (!msgid) {
    *msgid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (*msgid == -1) {
      ABORT("msgget");
    }
  }

  struct msgbuf *msgbuf = (struct msgbuf *)malloc(sizeof(long) + PAGE + size -
                                                  HDRLEN_MSG - HDRLEN_SEG);
  if (!msgbuf) {
    ABORT("malloc");
  }
  msgbuf->mtype = 1;

  int err = msgsnd(*msgid, msgbuf, PAGE + size - HDRLEN_MSG - HDRLEN_SEG, 0);
  if (err == -1) {
    ABORT("msgsnd");
  }

  free(msgbuf);
}

struct msgbuf *kfree_msg(int msgid, size_t size) {
  assert(size <= PAGE && size >= HDRLEN_MSG);

  struct msgbuf *msgbuf =
      (struct msgbuf *)malloc(sizeof(long) + size - HDRLEN_MSG);
  if (!msgbuf) {
    ABORT("malloc");
  }
  msgbuf->mtype = 1;

  int err = msgrcv(msgid, msgbuf, size - HDRLEN_MSG, 0, 0);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}

struct msgbuf *kfree_seg(int msgid, size_t size) {
  assert(size <= PAGE && size >= HDRLEN_SEG);

  struct msgbuf *msgbuf = (struct msgbuf *)malloc(sizeof(long) + PAGE + size -
                                                  HDRLEN_MSG - HDRLEN_SEG);
  if (!msgbuf) {
    ABORT("malloc");
  }
  msgbuf->mtype = 1;

  int err = msgrcv(msgid, msgbuf, PAGE + size - HDRLEN_MSG - HDRLEN_SEG, 0, 0);
  if (err == -1) {
    ABORT("msgrcv");
  }

  return msgbuf;
}
