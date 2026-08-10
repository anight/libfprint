/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "drivers/goodixqsee/goodix-qsee-proto.h"

#include <assert.h>
#include <string.h>

static void put32 (uint8_t *p, uint32_t v) { memcpy (p, &v, 4); }
static uint32_t get32 (uint8_t *p) { uint32_t v; memcpy (&v, p, 4); return v; }

int
main (void)
{
  uint8_t enumerate[GOODIX_QSEE_ENUMERATE_SIZE] = {0};
  uint8_t irq[GOODIX_QSEE_IRQ_SIZE] = {0};
  uint8_t response[GOODIX_QSEE_RESPONSE_SIZE] = {0};
  uint8_t enroll[180], hat[GOODIX_QSEE_HAT_SIZE] = {0};
  struct goodix_qsee_finger fingers[GOODIX_QSEE_ENUMERATE_MAX];
  struct goodix_qsee_irq_result result;
  bool mismatch;

  put32 (response, GOODIX_QSEE_TOO_FAST);
  assert (goodix_qsee_parse_response_status (response) == GOODIX_QSEE_TOO_FAST);
  put32 (response + 4, 1);
  assert (goodix_qsee_parse_response_status (response) == GOODIX_QSEE_TA_DEAD);

  put32 (enumerate + 100, 2);
  put32 (enumerate + 104, 3); put32 (enumerate + 144, 0x1234);
  put32 (enumerate + 112, 4); put32 (enumerate + 152, 0x5678);
  assert (goodix_qsee_parse_enumerate (enumerate, fingers, &mismatch) == 2);
  assert (!mismatch && fingers[0].group_id == 3 && fingers[1].finger_id == 0x5678);

  assert (goodix_qsee_prepare_irq (irq));
  assert (get32 (irq + 327049) == 0x02000000 && get32 (irq + 327616) == 1);
  put32 (irq + 12, GOODIX_QSEE_TOO_FAST); put32 (irq + 100, 1u << 7);
  put32 (irq + 0x4fce8, 0xabcdef01); put32 (irq + 0x4fcec, 4);
  assert (goodix_qsee_parse_irq (irq, &result));
  assert (result.status == GOODIX_QSEE_TOO_FAST && result.finger_id == 0xabcdef01 && result.samples_remaining == 4);

  put32 (hat + 1, 0x44332211);
  assert (goodix_qsee_build_enroll (enroll, sizeof (enroll), 7, hat));
  assert (get32 (enroll + 100) == 7 && !memcmp (enroll + 110, hat, sizeof (hat)));
  return 0;
}
