/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GOODIX_QSEE_PROFILE_V1 1u
#define GOODIX_QSEE_GROUP_DEFAULT 0u
#define GOODIX_QSEE_ENUMERATE_SIZE 184u
#define GOODIX_QSEE_ENUMERATE_MAX 10u
#define GOODIX_QSEE_IRQ_SIZE 327624u
#define GOODIX_QSEE_HAT_SIZE 69u
#define GOODIX_QSEE_RESPONSE_SIZE 8u

enum goodix_qsee_status {
  GOODIX_QSEE_SUCCESS = 0,
  GOODIX_QSEE_ACQUIRED_PARTIAL = 1011,
  GOODIX_QSEE_IMAGER_DIRTY_1012 = 1012,
  GOODIX_QSEE_DUPLICATE_FINGER = 1013,
  GOODIX_QSEE_DUPLICATE_AREA = 1045,
  GOODIX_QSEE_IMAGER_DIRTY_1052 = 1052,
  GOODIX_QSEE_IMAGER_DIRTY_1058 = 1058,
  GOODIX_QSEE_ACQUIRED_PARTIAL_1060 = 1060,
  GOODIX_QSEE_FINGER_NOT_EXIST = 1047,
  GOODIX_QSEE_TA_DEAD = 1049,
  GOODIX_QSEE_UNTRUSTED_ENROLL = 1057,
  GOODIX_QSEE_MATCH_FAIL_AND_RETRY = 1064,
  GOODIX_QSEE_TOO_FAST = 1094,
  GOODIX_QSEE_IMAGER_DIRTY_1101 = 1101,
  GOODIX_QSEE_IMAGER_DIRTY_1104 = 1104,
  GOODIX_QSEE_TOO_SLOW = 1117,
};

uint32_t goodix_qsee_parse_response_status (const uint8_t response[GOODIX_QSEE_RESPONSE_SIZE]);

struct goodix_qsee_finger {
  uint32_t group_id;
  uint32_t finger_id;
};

struct goodix_qsee_irq_result {
  uint32_t status;
  uint32_t mask;
  uint32_t operation;
  uint32_t group_id;
  uint32_t finger_id;
  uint32_t samples_remaining;
};

size_t goodix_qsee_parse_enumerate (const uint8_t payload[GOODIX_QSEE_ENUMERATE_SIZE],
                              struct goodix_qsee_finger out[GOODIX_QSEE_ENUMERATE_MAX],
                              bool *count_mismatch);
bool goodix_qsee_prepare_irq (uint8_t payload[GOODIX_QSEE_IRQ_SIZE]);
bool goodix_qsee_parse_irq (const uint8_t payload[GOODIX_QSEE_IRQ_SIZE],
                      struct goodix_qsee_irq_result *out);
bool goodix_qsee_build_enroll (uint8_t *payload, size_t size, uint32_t group_id,
                         const uint8_t hat[GOODIX_QSEE_HAT_SIZE]);
bool goodix_qsee_build_finger_command (uint8_t *payload, size_t size,
                                 uint32_t group_id, uint32_t finger_id);
