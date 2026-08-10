/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix-qsee-transport.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/tee.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define QSEECOM_IMPL_ID 5u

struct qsee_shm {
  int id;
  void *data;
  size_t size;
};

static void
shm_release (struct qsee_shm *shm)
{
  if (shm->data && shm->data != MAP_FAILED)
    munmap (shm->data, shm->size);
  memset (shm, 0, sizeof (*shm));
}

static int
shm_alloc (int fd, size_t size, struct qsee_shm *shm)
{
  struct tee_ioctl_shm_alloc_data data = { .size = size };
  int shm_fd = ioctl (fd, TEE_IOC_SHM_ALLOC, &data);

  if (shm_fd < 0)
    return -1;
  shm->data = mmap (NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    shm_fd, 0);
  close (shm_fd);
  if (shm->data == MAP_FAILED)
    return -1;
  shm->id = data.id;
  shm->size = data.size;
  memset (shm->data, 0, shm->size);
  return 0;
}

static int
open_client (void)
{
  struct tee_ioctl_version_data version;
  char path[32];
  int fd, i;

  for (i = 0; i < 8; i++)
    {
      snprintf (path, sizeof (path), "/dev/tee%d", i);
      fd = open (path, O_RDWR | O_CLOEXEC);
      if (fd < 0)
        continue;
      if (!ioctl (fd, TEE_IOC_VERSION, &version) &&
          version.impl_id == QSEECOM_IMPL_ID)
        return fd;
      close (fd);
    }
  errno = ENODEV;
  return -1;
}

int
goodix_qsee_qsee_open (struct goodix_qsee_qsee *qsee, const char *ta_name)
{
  struct {
    struct tee_ioctl_open_session_arg arg;
    struct tee_ioctl_param params[1];
  } request = {0};
  struct tee_ioctl_buf_data data;
  struct qsee_shm name = {0};
  int saved;

  if (!qsee || !ta_name || !*ta_name || strlen (ta_name) >= 64)
    { errno = EINVAL; return -1; }
  memset (qsee, 0, sizeof (*qsee));
  qsee->fd = open_client ();
  if (qsee->fd < 0 || shm_alloc (qsee->fd, 64, &name))
    goto fail;
  memcpy (name.data, ta_name, strlen (ta_name) + 1);
  request.arg.num_params = 1;
  request.params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
  request.params[0].b = strlen (ta_name) + 1;
  request.params[0].c = name.id;
  data.buf_ptr = (uintptr_t) &request;
  data.buf_len = sizeof (request);
  if (ioctl (qsee->fd, TEE_IOC_OPEN_SESSION, &data) || request.arg.ret)
    { if (!errno) errno = EIO; goto fail; }
  qsee->session = request.arg.session;
  shm_release (&name);
  return 0;
fail:
  saved = errno;
  shm_release (&name);
  if (qsee->fd >= 0) close (qsee->fd);
  qsee->fd = -1;
  errno = saved;
  return -1;
}

void
goodix_qsee_qsee_close (struct goodix_qsee_qsee *qsee)
{
  if (!qsee || qsee->fd < 0)
    return;
  if (qsee->session)
    {
      struct tee_ioctl_close_session_arg arg = { .session = qsee->session };
      ioctl (qsee->fd, TEE_IOC_CLOSE_SESSION, &arg);
    }
  close (qsee->fd);
  qsee->fd = -1;
  qsee->session = 0;
}

static void
build_header (struct goodix_qsee_qsee *qsee, uint8_t *header, uint32_t command,
              size_t payload_size)
{
  struct timespec now;
  struct tm local;
  uint64_t milliseconds = 0;
  time_t seconds;
  uint32_t value;

  memset (header, 0, 128);
  value = ++qsee->token; memcpy (header + 8, &value, 4);
  value = 1; memcpy (header + 12, &value, 4);
  if (!clock_gettime (CLOCK_REALTIME, &now))
    {
      seconds = now.tv_sec;
      if (localtime_r (&seconds, &local))
        milliseconds = ((uint64_t) local.tm_hour * 3600 +
                        (uint64_t) local.tm_min * 60 + local.tm_sec) * 1000 +
                       now.tv_nsec / 1000000;
    }
  memcpy (header + 16, &milliseconds, 8);
  memcpy (header + 32, &command, 4);
  value = (uint32_t) payload_size; memcpy (header + 36, &value, 4);
}

int
goodix_qsee_qsee_invoke (struct goodix_qsee_qsee *qsee, uint32_t command,
                   void *payload, size_t payload_size, uint32_t *status)
{
  struct {
    struct tee_ioctl_invoke_arg arg;
    struct tee_ioctl_param params[4];
  } request = {0};
  struct tee_ioctl_buf_data data;
  struct qsee_shm message = {0}, body = {0};
  int saved, rc = -1;

  if (!qsee || qsee->fd < 0 || !payload || !payload_size || payload_size > UINT32_MAX)
    { errno = EINVAL; return -1; }
  if (shm_alloc (qsee->fd, 4096, &message) ||
      shm_alloc (qsee->fd, payload_size, &body))
    goto out;
  build_header (qsee, message.data, command, payload_size);
  memcpy (body.data, payload, payload_size);
  request.arg.session = qsee->session;
  request.arg.num_params = 4;
  request.params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
  request.params[0].b = 128; request.params[0].c = message.id;
  request.params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
  request.params[1].a = 128; request.params[1].b = 64; request.params[1].c = message.id;
  request.params[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
  request.params[2].b = 4;
  request.params[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
  request.params[3].b = payload_size; request.params[3].c = body.id;
  data.buf_ptr = (uintptr_t) &request;
  data.buf_len = sizeof (request);
  if (ioctl (qsee->fd, TEE_IOC_INVOKE, &data) || request.arg.ret)
    { if (!errno) errno = EIO; goto out; }
  memcpy (payload, body.data, payload_size);
  if (status)
    *status = goodix_qsee_parse_response_status ((uint8_t *) message.data + 128);
  rc = 0;
out:
  saved = errno;
  shm_release (&body);
  shm_release (&message);
  errno = saved;
  return rc;
}
