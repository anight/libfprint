/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix-qsee-proto.h"

#include <string.h>

#define IRQ_MASK 100u
#define IRQ_OPERATION 104u
#define IRQ_ENROLL_GROUP 0x4fce4u
#define IRQ_ENROLL_FINGER 0x4fce8u
#define IRQ_ENROLL_REMAIN 0x4fcecu
#define IRQ_CTRL_MODE 327049u
#define IRQ_CTRL_SIZE 327096u
#define IRQ_CTRL_ARM 327616u

static uint32_t
get32 (const uint8_t *p)
{
  uint32_t value;
  memcpy (&value, p, sizeof (value));
  return value;
}

static void
put32 (uint8_t *p, uint32_t value)
{
  memcpy (p, &value, sizeof (value));
}

uint32_t
goodix_qsee_parse_response_status (const uint8_t response[GOODIX_QSEE_RESPONSE_SIZE])
{
  if (get32 (response + 4))
    return GOODIX_QSEE_TA_DEAD;

  return get32 (response);
}

size_t
goodix_qsee_parse_enumerate (const uint8_t payload[GOODIX_QSEE_ENUMERATE_SIZE],
                       struct goodix_qsee_finger out[GOODIX_QSEE_ENUMERATE_MAX],
                       bool *count_mismatch)
{
  uint32_t declared = get32 (payload + 100);
  size_t i, count = 0;

  for (i = 0; i < GOODIX_QSEE_ENUMERATE_MAX; i++)
    {
      uint32_t finger = get32 (payload + 144 + 4 * i);
      if (!finger)
        continue;
      out[count].group_id = get32 (payload + 104 + 4 * i);
      out[count].finger_id = finger;
      count++;
    }
  if (count_mismatch)
    *count_mismatch = declared != count;
  return count;
}

bool
goodix_qsee_prepare_irq (uint8_t payload[GOODIX_QSEE_IRQ_SIZE])
{
  put32 (payload + IRQ_CTRL_MODE, 0x02000000);
  put32 (payload + IRQ_CTRL_SIZE, 512);
  put32 (payload + IRQ_CTRL_ARM, 1);
  return true;
}

bool
goodix_qsee_parse_irq (const uint8_t payload[GOODIX_QSEE_IRQ_SIZE],
                 struct goodix_qsee_irq_result *out)
{
  if (!payload || !out)
    return false;
  out->status = get32 (payload + 12);
  out->mask = get32 (payload + IRQ_MASK);
  out->operation = get32 (payload + IRQ_OPERATION);
  out->group_id = get32 (payload + IRQ_ENROLL_GROUP);
  out->finger_id = get32 (payload + IRQ_ENROLL_FINGER);
  out->samples_remaining = get32 (payload + IRQ_ENROLL_REMAIN);
  return true;
}

bool
goodix_qsee_build_enroll (uint8_t *payload, size_t size, uint32_t group_id,
                    const uint8_t hat[GOODIX_QSEE_HAT_SIZE])
{
  if (!payload || !hat || size < 180)
    return false;
  memset (payload, 0, 180);
  put32 (payload + 100, group_id);
  memcpy (payload + 110, hat, GOODIX_QSEE_HAT_SIZE);
  return true;
}

bool
goodix_qsee_build_finger_command (uint8_t *payload, size_t size,
                            uint32_t group_id, uint32_t finger_id)
{
  if (!payload || size < 112)
    return false;
  memset (payload, 0, 112);
  put32 (payload + 100, group_id);
  put32 (payload + 104, finger_id);
  return true;
}
