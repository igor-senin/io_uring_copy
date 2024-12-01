#define _GNU_SOURCE

#include <liburing.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define SAFE_CALL(function_name, expression)                    \
  do {                                                          \
    if (unlikely((expression) < 0)) {                           \
      perror(#function_name);                                   \
      dprintf(STDERR_FILENO, "expression: %s \t on line %d\n",  \
              #expression, __LINE__);                           \
      exit(EXIT_FAILURE);                                       \
    }                                                           \
  } while (0)

#define BUFFER_SIZE (4 * 4096) /* размер буфферов чтения/записи */
#define QSIZE       256 /* размер SQ очереди */
#define TAKE_SIZE   (QSIZE >> 1) /* макс. кол-во CQE, забираемых за один раз */
#define IN_IDX      0 /* индекс ФД для чтения */
#define OUT_IDX     1 /* индекс ФД для записи */

enum : unsigned {
  READ,
  WRITE,
};

/* layout: |__read__|__write_|__io_common_data__|___iov_buffer___| */
typedef struct io_common_data {
  off_t length;
  off_t initial_offset;
  off_t bytes_read;
  off_t bytes_written;
  bool reading;
  bool writing;
} io_common_data_t;

typedef struct io_data {
  unsigned type;
  struct iovec iov;
} io_data_t;

static
off_t get_file_size(int fd) {
  struct stat statbuf;
  SAFE_CALL(fstat, fstat(fd, &statbuf));

  if (S_ISREG(statbuf.st_mode)) {
    return statbuf.st_size;
  }
  if (S_ISBLK(statbuf.st_mode)) {
    uint64_t bytes;
    SAFE_CALL(ioctl, ioctl(fd, BLKGETSIZE64, &bytes));
    return bytes;
  }

  return -1;
}

static
int prep_readv(struct io_uring_sqe* sqe, io_data_t* data) {
  sqe->flags |= IOSQE_FIXED_FILE;

  io_common_data_t* common = (io_common_data_t *) (data + 2);
  io_uring_prep_readv(sqe, IN_IDX, &data->iov, 1,
                      common->initial_offset + common->bytes_read);
  io_uring_sqe_set_data(sqe, data);

  return 0;
}

static
int prep_writev(struct io_uring_sqe* sqe, io_data_t* data) {
  sqe->flags |= IOSQE_FIXED_FILE;

  io_common_data_t* common = (io_common_data_t *) (data + 1);
  io_uring_prep_writev(sqe, OUT_IDX, &data->iov, 1,
                       common->initial_offset + common->bytes_written);
  io_uring_sqe_set_data(sqe, data);

  return 0;
}

static
off_t fill_with_readvs(struct io_uring* ring,
                       off_t fsize,
                       off_t offset,
                       size_t at_most,
                       size_t* unfinished)
{
  size_t cnt = 0;

  while (offset < fsize && cnt < at_most) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
      break;
    }

    off_t curlen = offset + BUFFER_SIZE > fsize ? fsize - offset : BUFFER_SIZE;
    off_t structs_len = 2 * sizeof(io_data_t) + sizeof(io_common_data_t);

    io_data_t* rdata = malloc(structs_len + curlen);
    if (rdata == NULL) {
      return -1;
    }

    memset(rdata, 0, structs_len);
    io_common_data_t* common = (io_common_data_t *) (rdata + 2);
    io_data_t* wdata = rdata + 1;

    rdata->type = READ;
    rdata->iov.iov_len = curlen;
    rdata->iov.iov_base = (char*)rdata + structs_len;
    wdata->type = WRITE;
    wdata->iov.iov_len = curlen;
    wdata->iov.iov_base = (char*)rdata + structs_len;
    common->length = curlen;
    common->initial_offset = offset;
    common->bytes_read = common->bytes_written = 0;
    common->reading = true;
    common->writing = false;

    prep_readv(sqe, rdata);

    ++ *unfinished;
    ++cnt;
    offset += curlen;
  }

  return offset;
}

static
int dispatch_event(
  struct io_uring* ring,
  struct io_uring_cqe* cqe,
  io_data_t* data,
  io_common_data_t* common,
  off_t* insize,
  off_t* outsize,
  size_t* unfinished)
{
  switch (data->type) {
  case READ:
    // Если не дочитали до конца, готовим новую операцию чтения;
    //    иначе останавливаемся.
    // Если запись ещё не запущена (а мы что-то прочитали), надо запустить.
    assert(common->reading);

    ssize_t bytes_read = cqe->res;

    if (bytes_read < 0) {
      return -1;
    }

    *insize += bytes_read;
    data->iov.iov_base = (char*)data->iov.iov_base + bytes_read;
    data->iov.iov_len -= bytes_read;
    common->bytes_read += bytes_read;

    if (common->bytes_read < common->length) {
      struct io_uring_sqe* sqe_read = io_uring_get_sqe(ring);
      assert(sqe_read != NULL);
      prep_readv(sqe_read, data);
    } else {
      common->reading = false;
    }

    if (!common->writing) {
      struct io_uring_sqe* sqe_write = io_uring_get_sqe(ring);
      assert(sqe_write != NULL);
      common->writing = true;
      prep_writev(sqe_write, data + 1);
    }

    break;

  case WRITE:
    // Если дошли до конца прочитанного, то по логике приложения:
    //    либо чтение ещё запущено и оно перезапустит запись
    //    ,
    //    либо записали всё, что надо.
    //
    // Если не дошли до конца прочитанного, то перезапускаем сами себя.
    assert(common->writing);

    ssize_t bytes_written = cqe->res;

    if (bytes_written <= 0) {
      errno = EIO;
      return -1;
    }

    *outsize -= bytes_written;
    data->iov.iov_base = (char*)data->iov.iov_base + bytes_written;
    data->iov.iov_len -= bytes_written;
    common->bytes_written += bytes_written;

    if (common->bytes_written != common->bytes_read) {
      struct io_uring_sqe* sqe_write = io_uring_get_sqe(ring);
      assert(sqe_write != NULL);
      prep_writev(sqe_write, data);
    } else {
      common->writing = false;
      if (common->bytes_written == common->length) {
        -- *unfinished;
        free(data - 1);
      }
    }

    break;

  default:
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* Инвариант: одновременно засабмиченных групп операций
 * (то есть READ / READ + WRITE / WRITE)
 * может быть не более QSIZE. */
void event_loop(struct io_uring* ring, off_t fsize) {
  off_t curr_offset = 0;
  off_t insize = 0;
  off_t outsize = fsize;
  size_t unfinished_blocks = 0; /* число submitted, но не прочитанных групп операций */
  struct io_uring_cqe* cqe;
  struct io_uring_cqe* cqes[TAKE_SIZE];

  while (insize < fsize || outsize > 0 || unfinished_blocks > 0) {
    assert(unfinished_blocks <= QSIZE);
    SAFE_CALL(fill_with_readvs, /* дозаполняем SQRing операциями чтения */
              curr_offset = fill_with_readvs(ring, fsize,
                                             curr_offset,
                                             QSIZE - unfinished_blocks,
                                             &unfinished_blocks)
              );
    /* сабмитим операции */
    SAFE_CALL(io_uring_submit, io_uring_submit(ring));
    /* ждём завершения хотя бы одной */
    SAFE_CALL(io_uring_wait_cqe, io_uring_wait_cqe(ring, &cqe));

    unsigned cqe_count = io_uring_peek_batch_cqe(ring, cqes, TAKE_SIZE);
    for (unsigned i = 0; i < cqe_count; ++i) {
      cqe = cqes[i];

      io_data_t* data = (io_data_t *) io_uring_cqe_get_data(cqe);
      io_common_data_t* common
        = (io_common_data_t *) (data + (data->type == READ ? 2 : 1));

      SAFE_CALL(dispatch_event, dispatch_event(ring, cqe, data, common,
                                               &insize, &outsize,
                                               &unfinished_blocks)
                );

      io_uring_cqe_seen(ring, cqe);
    }
  }
}


int main(int argc, char* argv[]) {
  if (argc < 3) {
    dprintf(STDERR_FILENO, "Usage: %s <input-file> <output-file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  int fdin, fdout;
  SAFE_CALL(open, fdin = open(argv[1], O_RDONLY));
  SAFE_CALL(open, fdout = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644));

  struct io_uring_params params;
  struct io_uring ring;
  memset(&params, 0, sizeof(struct io_uring_params));

  SAFE_CALL(io_uring_queue_init_params,
            io_uring_queue_init_params(QSIZE, &ring, &params)
            );

  int fds[] = {fdin, fdout};
  SAFE_CALL(io_uring_register,
            io_uring_register(ring.ring_fd,
                              IORING_REGISTER_FILES,
                              fds, 2
                              )
            );
  // SAFE_CALL(io_uring_register,
  //           io_uring_register(ring.ring_fd,
  //                             IORING_REGISTER_BUFFERS,
  //                             /*TODO*/NULL, 0
  //                             )
  //           );

  off_t fsize;
  SAFE_CALL(get_file_size, fsize = get_file_size(fdin));

  /* main call */
  event_loop(&ring, fsize);

  // io_uring_register(ring.ring_fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
  io_uring_register(ring.ring_fd, IORING_UNREGISTER_FILES, NULL, 0);
  io_uring_queue_exit(&ring);

  close(fdout);
  close(fdin);

  exit(EXIT_SUCCESS);

}
