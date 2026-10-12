/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct goodix_qsee_qsee {
  int fd;
  uint32_t session;
  uint32_t token;
  uint32_t profile;
};

int goodix_qsee_qsee_open (struct goodix_qsee_qsee *qsee, const char *ta_name);
void goodix_qsee_qsee_close (struct goodix_qsee_qsee *qsee);
int goodix_qsee_qsee_invoke (struct goodix_qsee_qsee *qsee, uint32_t command,
                       void *payload, size_t payload_size, uint32_t *status);
