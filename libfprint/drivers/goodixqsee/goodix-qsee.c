/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define FP_COMPONENT "goodixqsee"

#include "drivers_api.h"
#include "goodix-qsee.h"
#include "goodix-qsee-proto.h"

#include <errno.h>
#include <string.h>

#define CMD_DETECT_SENSOR 1000u
#define CMD_INIT 1001u
#define CMD_INIT_FINISHED 1005u
#define CMD_PRE_ENROLL 1006u
#define CMD_ENROLL 1007u
#define CMD_CANCEL 1009u
#define CMD_AUTHENTICATE 1010u
#define CMD_GET_AUTH_ID 1011u
#define CMD_SAVE 1012u
#define CMD_REMOVE 1013u
#define CMD_SET_ACTIVE_GROUP 1014u
#define CMD_ENUMERATE 1015u
#define CMD_GET_DEV_INFO 1089u
#define CMD_AUTHENTICATE_FINISH 1086u

#define IRQ_FINGER_DOWN (1u << 1)
#define IRQ_FINGER_UP (1u << 2)
#define IRQ_IMAGE (1u << 7)
#define IRQ_FRAME_DONE (1u << 10)
#define IRQ_MAX_DRAIN 12
#define ENROLL_STAGES_PROFILE_V1 25
#define ENROLL_STAGES_FINGERPR 8
#define FINGERPR_OTP_PATH "/var/lib/flex5g-fp-linux/gf_otp_info"

enum worker_operation { WORK_OPEN, WORK_CLOSE, WORK_LIST, WORK_DELETE,
                        WORK_ENROLL, WORK_IDENTIFY, WORK_CLEAR };

struct worker_data {
  enum worker_operation operation;
  guint32 group_id;
  guint32 finger_id;
};

struct list_result {
  size_t count;
  bool count_mismatch;
  struct goodix_qsee_finger fingers[GOODIX_QSEE_ENUMERATE_MAX];
};

struct interactive_result {
  guint32 group_id;
  guint32 finger_id;
  guint32 status;
  gboolean adopted_existing;
};

struct progress_event {
  FpiDeviceGoodixQsee *self;
  FpFingerStatusFlags finger_status;
  gint completed;
  GError *retry;
};

G_DEFINE_TYPE (FpiDeviceGoodixQsee, fpi_device_goodixqsee, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_MISC,
    .misc_name = "goodix_fp", .misc_compatible = "goodix,gf3626",
    .driver_data = GOODIX_QSEE_PROFILE_V1 },
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_MISC,
    .misc_name = "goodix_fp", .misc_compatible = "goodix,gxfp55a4",
    .driver_data = GOODIX_QSEE_PROFILE_FINGERPR },
  { .udev_types = 0 }
};

static GError *
io_error (const char *operation)
{
  return g_error_new (G_IO_ERROR, g_io_error_from_errno (errno),
                      "%s: %s", operation, g_strerror (errno));
}

static gboolean
invoke (FpiDeviceGoodixQsee *self, guint32 command, guint8 *payload,
        gsize size, guint32 *status, GError **error)
{
  guint32 result = 0;

  if (goodix_qsee_qsee_invoke (&self->qsee, command, payload, size, &result))
    {
      g_propagate_error (error, io_error ("QSEE invoke"));
      return FALSE;
    }
  if (status) *status = result;
  return TRUE;
}

static gboolean
invoke_success (FpiDeviceGoodixQsee *self, guint32 command, guint8 *payload,
                gsize size, GError **error)
{
  guint32 status;
  if (!invoke (self, command, payload, size, &status, error))
    return FALSE;
  if (status)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Goodix command %u returned status %u", command, status);
      return FALSE;
    }
  return TRUE;
}

static gchar *
read_ta_name (FpDevice *device, GError **error)
{
  const gchar *sysfs = fpi_device_get_udev_sysfs_path (device,
                                                       FPI_DEVICE_UDEV_SUBTYPE_MISC);
  g_autofree gchar *direct = NULL;
  g_autofree gchar *parent = NULL;
  g_autofree gchar *platform = NULL;
  gchar *contents = NULL;

  if (fpi_device_get_driver_data (device) == GOODIX_QSEE_PROFILE_FINGERPR)
    return g_strdup ("fingerpr");

  if (!sysfs)
    { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                           "misc device has no sysfs path"); return NULL; }
  direct = g_build_filename (sysfs, "firmware_name", NULL);
  parent = g_build_filename (sysfs, "device", "firmware_name", NULL);
  platform = g_canonicalize_filename ("../firmware_name", sysfs);
  if (!g_file_get_contents (direct, &contents, NULL, NULL) &&
      !g_file_get_contents (parent, &contents, NULL, NULL) &&
      !g_file_get_contents (platform, &contents, NULL, error))
    return NULL;
  g_strstrip (contents);
  if (!*contents)
    { g_free (contents); g_set_error_literal (error, G_IO_ERROR,
                                              G_IO_ERROR_INVALID_DATA,
                                              "firmware_name is empty"); return NULL; }
  return contents;
}

static gboolean
bring_up (FpiDeviceGoodixQsee *self, GError **error)
{
  static const struct { guint32 command; gsize size; } sequence[] = {
    { CMD_DETECT_SENSOR, 520 }, { CMD_INIT, 348 },
    { CMD_INIT_FINISHED, 104 }, { CMD_GET_DEV_INFO, 5500 },
  };
  g_autofree guint8 *payload = g_malloc0 (5500);
  guint i;

  if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
    {
      g_autofree gchar *otp = NULL;
      gsize otp_size = 0;
      guint32 length = 32;
      static const struct { guint32 command; gsize size; } fingerpr_sequence[] = {
        { 1097, 120 }, { CMD_DETECT_SENSOR, 380 },
        { CMD_INIT, 204 }, { CMD_INIT_FINISHED, 168 },
      };
      if (!g_file_get_contents (FINGERPR_OTP_PATH, &otp, &otp_size, error))
        return FALSE;
      if (otp_size != 33)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "GF3268 OTP backup must be 33 bytes");
          return FALSE;
        }
      for (i = 0; i < G_N_ELEMENTS (fingerpr_sequence); i++)
        {
          memset (payload, 0, fingerpr_sequence[i].size);
          if (fingerpr_sequence[i].command == CMD_INIT)
            {
              memcpy (payload + 132, otp, 32);
              memcpy (payload + 196, &length, 4);
            }
          if (!invoke_success (self, fingerpr_sequence[i].command, payload,
                               fingerpr_sequence[i].size, error))
            return FALSE;
        }
      return TRUE;
    }

  for (i = 0; i < G_N_ELEMENTS (sequence); i++)
    {
      memset (payload, 0, sequence[i].size);
      if (!invoke_success (self, sequence[i].command, payload,
                           sequence[i].size, error))
        return FALSE;
    }
  return TRUE;
}

static gboolean
set_group (FpiDeviceGoodixQsee *self, guint32 group, GError **error)
{
  if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
    {
      guint8 payload[440] = {0};
      memcpy (payload + 96, &group, 4);
      g_strlcpy ((gchar *) payload + 184, "flex5g-linux", sizeof (payload) - 184);
      return invoke_success (self, CMD_SET_ACTIVE_GROUP, payload,
                             sizeof (payload), error);
    }
  guint8 payload[104] = {0};
  memcpy (payload + 100, &group, sizeof (group));
  return invoke_success (self, CMD_SET_ACTIVE_GROUP, payload, sizeof (payload), error);
}

static GError *
retry_for_status (guint32 status)
{
  switch (status)
    {
    case GOODIX_QSEE_TOO_FAST:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_FAST);
    case GOODIX_QSEE_TOO_SLOW:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);
    case GOODIX_QSEE_DUPLICATE_AREA:
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                       "Fingerprint area already sampled");
    case GOODIX_QSEE_DUPLICATE_FINGER:
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                       "Finger is already enrolled");
    case GOODIX_QSEE_ACQUIRED_PARTIAL:
    case GOODIX_QSEE_ACQUIRED_PARTIAL_1060:
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    case GOODIX_QSEE_IMAGER_DIRTY_1012:
    case GOODIX_QSEE_IMAGER_DIRTY_1052:
    case GOODIX_QSEE_IMAGER_DIRTY_1058:
    case GOODIX_QSEE_IMAGER_DIRTY_1101:
    case GOODIX_QSEE_IMAGER_DIRTY_1104:
      return fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);
    default:
      return status ? fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                                "Goodix sample status %u", status) : NULL;
    }
}

static gboolean
progress_in_main (gpointer user_data)
{
  struct progress_event *event = user_data;
  fpi_device_report_finger_status (FP_DEVICE (event->self), event->finger_status);
  if (event->completed >= 0 || event->retry)
    fpi_device_enroll_progress (FP_DEVICE (event->self), MAX (event->completed, 0),
                                NULL, g_steal_pointer (&event->retry));
  g_object_unref (event->self);
  g_free (event);
  return G_SOURCE_REMOVE;
}

static void
queue_progress (FpiDeviceGoodixQsee *self, FpFingerStatusFlags finger_status,
                gint completed, GError *retry)
{
  struct progress_event *event = g_new0 (struct progress_event, 1);
  event->self = g_object_ref (self);
  event->finger_status = finger_status;
  event->completed = completed;
  event->retry = retry;
  g_main_context_invoke (NULL, progress_in_main, event);
}

static void
cancel_armed (FpiDeviceGoodixQsee *self)
{
  guint8 payload[104] = {0};
  guint32 ignored;
  goodix_qsee_qsee_invoke (&self->qsee, CMD_CANCEL, payload,
                          self->profile == GOODIX_QSEE_PROFILE_FINGERPR ? 100 :
                          sizeof (payload), &ignored);
}

static gboolean
finish_authentication (FpiDeviceGoodixQsee *self, const guint8 *context,
                       GError **error)
{
  guint8 payload[124] = {0};
  guint32 value;
  memcpy (&value, context + 100, 4); value = GUINT32_TO_BE (value); memcpy (payload + 104, &value, 4);
  memcpy (&value, context + 104, 4); value = GUINT32_TO_BE (value); memcpy (payload + 108, &value, 4);
  memcpy (payload + 112, context + 0x4fce4, 4);
  memcpy (payload + 116, context + 0x4fce8, 4);
  return invoke_success (self, CMD_AUTHENTICATE_FINISH, payload, sizeof (payload), error);
}

/* fingerpr answers a request about templates with this status when their
 * secure object does not exist: nothing is enrolled yet, or the template is
 * already gone. */
#define GF_ERROR_OPEN_SECURE_OBJECT_FAILED 1033u

/* Enumerate the fingerpr templates into body (44500 bytes). A store without
 * any template is an empty list, not an error; otherwise the first finger
 * could never be enrolled. */
static gboolean
fingerpr_enumerate (FpiDeviceGoodixQsee *self, guint8 *body, guint32 *count,
                    GError **error)
{
  guint32 status;

  memset (body, 0, 44500);
  if (!invoke (self, CMD_ENUMERATE, body, 44500, &status, error))
    return FALSE;
  if (status == GF_ERROR_OPEN_SECURE_OBJECT_FAILED)
    {
      *count = 0;
      return TRUE;
    }
  if (status)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Goodix command %u returned status %u", CMD_ENUMERATE, status);
      return FALSE;
    }
  memcpy (count, body + 4296, 4);
  return TRUE;
}

static gboolean
fingerpr_next_slot (FpiDeviceGoodixQsee *self, guint32 *slot, GError **error)
{
  g_autofree guint8 *body = g_malloc0 (44500);
  gboolean used[10] = {0};
  guint32 count;

  if (!fingerpr_enumerate (self, body, &count, error))
    return FALSE;
  if (count > 10)
    { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "fingerpr returned too many templates"); return FALSE; }
  for (guint32 i = 0; i < count; i++)
    {
      guint32 id;
      memcpy (&id, body + 24500 + i * 400, 4);
      if (id >= 245 && id <= 254) used[id - 245] = TRUE;
    }
  for (guint32 i = 0; i < 10; i++)
    if (!used[i]) { *slot = 245 + i; return TRUE; }
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
                       "all ten fingerpr template slots are occupied");
  return FALSE;
}

static gboolean
fingerpr_slot_exists (FpiDeviceGoodixQsee *self, guint32 slot, GError **error)
{
  g_autofree guint8 *body = g_malloc0 (44500);
  guint32 count;

  if (!fingerpr_enumerate (self, body, &count, error))
    return FALSE;
  if (count > GOODIX_QSEE_ENUMERATE_MAX)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "fingerpr returned too many templates");
      return FALSE;
    }
  for (guint32 i = 0; i < count; i++)
    {
      guint32 found;
      memcpy (&found, body + 24500 + i * 400, 4);
      if (found == slot)
        return TRUE;
    }
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
               "fingerpr template %u is not present", slot);
  return FALSE;
}

static gboolean
fingerpr_commit_save (FpiDeviceGoodixQsee *self, guint32 slot,
                      GError **error)
{
  static const guint8 sid[16] = {1, 2, 0, 0, 0, 0, 0, 22,
                                 1, 0, 0, 0, 0xe8, 3, 0, 0};
  guint8 commit[276] = {0}, save[192] = {0};
  guint32 length = sizeof (sid), group;

  memcpy (commit + 104, sid, sizeof (sid));
  memcpy (commit + 184, &length, 4);
  memcpy (commit + 188, &slot, 4);
  if (!invoke_success (self, 1094, commit, sizeof (commit), error))
    return FALSE;
  memcpy (&group, commit + 100, 4);
  memcpy (save + 96, &length, 4);
  memcpy (save + 100, sid, sizeof (sid));
  memcpy (save + 180, &group, 4);
  memcpy (save + 184, &slot, 4);
  return invoke_success (self, CMD_SAVE, save, sizeof (save), error);
}

static gboolean
fingerpr_remove (FpiDeviceGoodixQsee *self, guint32 finger,
                 GError **error)
{
  static const guint8 sid[16] = {1, 2, 0, 0, 0, 0, 0, 22,
                                 1, 0, 0, 0, 0xe8, 3, 0, 0};
  guint8 body[996] = {0};
  guint32 length = sizeof (sid), status;
  memcpy (body + 100, sid, sizeof (sid));
  memcpy (body + 180, &length, 4);
  memcpy (body + 188, &finger, 4);
  if (!invoke (self, CMD_REMOVE, body, sizeof (body), &status, error))
    return FALSE;
  /* A template that is not there is removed. */
  if (status && status != GF_ERROR_OPEN_SECURE_OBJECT_FAILED)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Goodix command %u returned status %u", CMD_REMOVE, status);
      return FALSE;
    }
  return TRUE;
}

static struct interactive_result *
capture_fingerpr (FpiDeviceGoodixQsee *self, gboolean enrolling,
                  GCancellable *cancellable, GError **error)
{
  const gsize irq_size = 0x451f8;
  g_autofree guint8 *irq = g_malloc0 (irq_size);
  struct interactive_result *result = NULL;
  gint64 deadline = g_get_monotonic_time () +
                    (enrolling ? 120 : 30) * G_TIME_SPAN_SECOND;
  guint32 slot = 0;
  gboolean armed = FALSE;
  const gchar *adopt_setting = g_getenv ("FLEX5G_FP_ADOPT_EXISTING");
  gboolean adopting = enrolling && adopt_setting != NULL;

  if (!set_group (self, GOODIX_QSEE_GROUP_DEFAULT, error)) return NULL;
  if (adopting)
    {
      if (g_strcmp0 (adopt_setting, "245") != 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                               "only explicit adoption of template 245 is supported");
          return NULL;
        }
      slot = 245;
      if (!fingerpr_slot_exists (self, slot, error)) return NULL;
    }
  else if (enrolling)
    {
      guint8 body[272] = {0};
      if (!fingerpr_next_slot (self, &slot, error) ||
          !invoke_success (self, CMD_ENROLL, body, sizeof (body), error))
        return NULL;
    }
  if (!enrolling || adopting)
    {
      guint8 body[200] = {0};
      guint32 any_finger = UINT32_MAX;
      memcpy (body + 192, &any_finger, 4);
      if (!invoke_success (self, CMD_AUTHENTICATE, body,
                           sizeof (body), error)) return NULL;
    }
  armed = TRUE;
  if (goodix_qsee_sensor_enable_irq (&self->sensor))
    { g_propagate_error (error, io_error ("enabling Goodix IRQ")); goto out; }
  while (g_get_monotonic_time () < deadline)
    {
      int wait;
      if (g_cancellable_is_cancelled (cancellable))
        { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                               "Operation cancelled"); goto out; }
      wait = goodix_qsee_sensor_wait_irq (&self->sensor, 250);
      if (wait < 0)
        { g_propagate_error (error, io_error ("waiting for Goodix IRQ")); goto out; }
      if (!wait) continue;
      memset (irq, 0, irq_size);
      memcpy (irq + 0x44fb8, &(guint32){2}, 4);
      memcpy (irq + 0x44fe8, &(guint32){512}, 4);
      memcpy (irq + 0x451f0, &(guint32){1}, 4);
      for (guint pass = 0; pass < 8; pass++)
        {
          guint32 status, mask, operation, step, group, finger;
          if (!invoke (self, 1016, irq, irq_size, &status, error)) goto out;
          memcpy (&mask, irq + 96, 4);
          memcpy (&operation, irq + 100, 4);
          memcpy (&step, irq + 0x451f0, 4);
          memcpy (&group, irq + 0x44f28, 4);
          memcpy (&finger, irq + 0x44f2c, 4);
          fp_dbg ("fingerpr IRQ mask=0x%08x op=%u status=%u group=%u finger=%u step=%u",
                  mask, operation, status, group, finger, step);
          if (mask & IRQ_FINGER_DOWN)
            queue_progress (self, FP_FINGER_STATUS_PRESENT, -1, NULL);
          if (mask & IRQ_FINGER_UP)
            queue_progress (self, FP_FINGER_STATUS_NONE, -1, NULL);
          if (enrolling && !status && (mask & IRQ_IMAGE) &&
              operation == 0 && step == 7)
            {
              guint8 sample[200] = {0};
              guint32 sample_status, duplicate;
              guint16 remaining;
              if (!invoke (self, 1093, sample, sizeof (sample),
                           &sample_status, error)) goto out;
              memcpy (&remaining, sample + 192, 2);
              memcpy (&duplicate, sample + 196, 4);
              if (sample_status || duplicate)
                {
                  queue_progress (self, FP_FINGER_STATUS_PRESENT, -1,
                                  retry_for_status (sample_status ? sample_status :
                                                    GOODIX_QSEE_DUPLICATE_FINGER));
                  break;
                }
              queue_progress (self, FP_FINGER_STATUS_PRESENT,
                              CLAMP (8 - (gint) remaining, 0, 8), NULL);
              if (!remaining)
                {
                  if (!fingerpr_commit_save (self, slot, error)) goto out;
                  result = g_new0 (struct interactive_result, 1);
                  result->group_id = 0;
                  result->finger_id = slot;
                  goto out;
                }
              break;
            }
          if ((!enrolling || adopting) && (mask & IRQ_IMAGE) &&
              operation == 1 && step == 7)
            {
              if (adopting)
                {
                  if (status || group != GOODIX_QSEE_GROUP_DEFAULT ||
                      finger != slot)
                    {
                      queue_progress (self, FP_FINGER_STATUS_PRESENT, -1,
                                      fpi_device_retry_new_msg (
                                        FP_DEVICE_RETRY_GENERAL,
                                        "Touched finger does not match the existing Linux template"));
                      break;
                    }
                  result = g_new0 (struct interactive_result, 1);
                  result->group_id = group;
                  result->finger_id = finger;
                  result->adopted_existing = TRUE;
                  goto out;
                }
              result = g_new0 (struct interactive_result, 1);
              result->group_id = group;
              result->finger_id = finger;
              result->status = status ? status :
                               finger ? 0 : GOODIX_QSEE_MATCH_FAIL_AND_RETRY;
              goto out;
            }
          if (status) break;
          if (step == 3 || step == 4 || step == 5) continue;
          if ((mask & IRQ_FINGER_DOWN) && step == 7 &&
              (operation == 0 || operation == 1 || operation == 2 ||
               operation == 4 || operation == 28 || operation == 32 ||
               operation == 33 || operation == 34))
            { memcpy (irq + 0x451f0, &(guint32){2}, 4); continue; }
          break;
        }
    }
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                       "Fingerprint operation timed out");
out:
  if (armed) cancel_armed (self);
  queue_progress (self, FP_FINGER_STATUS_NONE, -1, NULL);
  return result;
}

static struct interactive_result *
capture_operation (FpiDeviceGoodixQsee *self, gboolean enrolling,
                   GCancellable *cancellable, GError **error)
{
  if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
    return capture_fingerpr (self, enrolling, cancellable, error);
  g_autofree guint8 *irq = g_malloc0 (GOODIX_QSEE_IRQ_SIZE);
  struct interactive_result *result = NULL;
  gint64 deadline = g_get_monotonic_time () + (enrolling ? 120 : 30) * G_TIME_SPAN_SECOND;
  gboolean armed = FALSE;
  guint32 status = 0;

  if (!set_group (self, GOODIX_QSEE_GROUP_DEFAULT, error)) return NULL;
  if (enrolling)
    {
      guint8 pre[112] = {0}, enroll[180], hat[GOODIX_QSEE_HAT_SIZE];
      guint64 challenge;
      if (!invoke_success (self, CMD_PRE_ENROLL, pre, sizeof (pre), error)) return NULL;
      memcpy (&challenge, pre + 104, sizeof (challenge));
      if (!challenge || !self->token_provider (challenge, hat, error, self->token_provider_data) ||
          !goodix_qsee_build_enroll (enroll, sizeof (enroll), GOODIX_QSEE_GROUP_DEFAULT, hat) ||
          !invoke_success (self, CMD_ENROLL, enroll, sizeof (enroll), error)) return NULL;
    }
  else
    {
      guint8 auth[112] = {0};
      memcpy (auth + 100, &(guint32){GOODIX_QSEE_GROUP_DEFAULT}, 4);
      if (!invoke_success (self, CMD_AUTHENTICATE, auth, sizeof (auth), error)) return NULL;
    }
  armed = TRUE;
  if (goodix_qsee_sensor_enable_irq (&self->sensor))
    { g_propagate_error (error, io_error ("enabling Goodix IRQ")); goto out; }
  goodix_qsee_prepare_irq (irq);
  while (g_get_monotonic_time () < deadline)
    {
      int wait, drain;
      if (g_cancellable_is_cancelled (cancellable))
        { g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled"); goto out; }
      wait = goodix_qsee_sensor_wait_irq (&self->sensor, 250);
      if (wait < 0) { g_propagate_error (error, io_error ("waiting for Goodix IRQ")); goto out; }
      if (!wait) continue;
      for (drain = 0; drain < IRQ_MAX_DRAIN; drain++)
        {
          struct goodix_qsee_irq_result event;
          goodix_qsee_prepare_irq (irq);
          if (!invoke (self, 1016, irq, GOODIX_QSEE_IRQ_SIZE, &status, error)) goto out;
          goodix_qsee_parse_irq (irq, &event);
          event.status = status;
          fp_dbg ("IRQ drain %d: mask=0x%08x operation=%u status=%u group=%u finger=%u remaining=%u",
                  drain, event.mask, event.operation, event.status,
                  event.group_id, event.finger_id, event.samples_remaining);
          if (!event.mask) break;
          if (event.mask & IRQ_FINGER_DOWN)
            queue_progress (self, FP_FINGER_STATUS_PRESENT, -1, NULL);
          if (event.mask & IRQ_FINGER_UP)
            queue_progress (self, FP_FINGER_STATUS_NONE, -1, NULL);
          if (!(event.mask & (IRQ_IMAGE | IRQ_FRAME_DONE))) continue;
          if (enrolling)
            {
              gint completed = CLAMP (ENROLL_STAGES_PROFILE_V1 -
                                      (gint) event.samples_remaining,
                                      0, ENROLL_STAGES_PROFILE_V1);
              queue_progress (self, FP_FINGER_STATUS_PRESENT, completed,
                              retry_for_status (event.status));
              if (!event.samples_remaining && event.finger_id)
                {
                  guint8 save[112];
                  goodix_qsee_build_finger_command (save, sizeof (save), event.group_id, event.finger_id);
                  if (!invoke_success (self, CMD_SAVE, save, sizeof (save), error)) goto out;
                  {
                    g_autoptr(GError) refresh_error = NULL;
                    guint8 auth_id[112] = {0};
                    if (!set_group (self, event.group_id, &refresh_error) ||
                        !invoke_success (self, CMD_GET_AUTH_ID, auth_id,
                                         sizeof (auth_id), &refresh_error))
                      fp_warn ("Enrollment saved but auth-id refresh failed: %s",
                               refresh_error->message);
                  }
                  result = g_new0 (struct interactive_result, 1);
                  result->group_id = event.group_id; result->finger_id = event.finger_id;
                  armed = FALSE;
                  goto out;
                }
            }
          else
            {
              result = g_new0 (struct interactive_result, 1);
              result->status = event.status;
              result->group_id = event.group_id; result->finger_id = event.finger_id;
              if (!event.status && !finish_authentication (self, irq, error))
                { g_clear_pointer (&result, g_free); goto out; }
              armed = FALSE;
              goto out;
            }
        }
    }
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Fingerprint operation timed out");
out:
  if (armed) cancel_armed (self);
  queue_progress (self, FP_FINGER_STATUS_NONE, -1, NULL);
  return result;
}

static void
worker_thread (GTask *task, gpointer object, gpointer task_data,
               GCancellable *cancellable)
{
  FpiDeviceGoodixQsee *self = object;
  struct worker_data *work = task_data;
  g_autoptr(GError) error = NULL;

  if (g_task_return_error_if_cancelled (task)) return;
  switch (work->operation)
    {
    case WORK_OPEN:
      self->profile = fpi_device_get_driver_data (FP_DEVICE (self));
      if (!self->ta_name)
        self->ta_name = read_ta_name (FP_DEVICE (self), &error);
      if (!self->ta_name) break;
      if (goodix_qsee_sensor_open (&self->sensor,
                                   fpi_device_get_udev_data (FP_DEVICE (self),
                                                            FPI_DEVICE_UDEV_SUBTYPE_MISC)))
        { error = io_error ("opening Goodix sensor"); break; }
      if (goodix_qsee_qsee_open (&self->qsee, self->ta_name))
        { error = io_error ("opening Goodix TA"); break; }
      self->qsee.profile = self->profile;
      if (!bring_up (self, &error)) break;
      g_task_return_boolean (task, TRUE);
      return;
    case WORK_CLOSE:
      goodix_qsee_qsee_close (&self->qsee);
      goodix_qsee_sensor_close (&self->sensor);
      g_task_return_boolean (task, TRUE);
      return;
    case WORK_LIST:
      {
        gsize size = self->profile == GOODIX_QSEE_PROFILE_FINGERPR ?
                     44500 : GOODIX_QSEE_ENUMERATE_SIZE;
        g_autofree guint8 *payload = g_malloc0 (size);
        struct list_result *result = g_new0 (struct list_result, 1);
        guint32 count = 0;
        if (!set_group (self, work->group_id, &error) ||
            !(self->profile == GOODIX_QSEE_PROFILE_FINGERPR ?
              fingerpr_enumerate (self, payload, &count, &error) :
              invoke_success (self, CMD_ENUMERATE, payload, size, &error)))
          { g_free (result); break; }
        if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
          {
            result->count_mismatch = count > GOODIX_QSEE_ENUMERATE_MAX;
            result->count = MIN (count, GOODIX_QSEE_ENUMERATE_MAX);
            for (size_t i = 0; i < result->count; i++)
              {
                result->fingers[i].group_id = work->group_id;
                memcpy (&result->fingers[i].finger_id,
                        payload + 24500 + i * 400, 4);
              }
          }
        else
          result->count = goodix_qsee_parse_enumerate (payload, result->fingers,
                                                       &result->count_mismatch);
        g_task_return_pointer (task, result, g_free);
        return;
      }
    case WORK_DELETE:
      {
        if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
          {
            if (!set_group (self, work->group_id, &error) ||
                !fingerpr_remove (self, work->finger_id, &error))
              break;
            g_task_return_boolean (task, TRUE);
            return;
          }
        guint8 payload[112];
        goodix_qsee_build_finger_command (payload, sizeof (payload),
                                          work->group_id, work->finger_id);
        if (!invoke_success (self, CMD_REMOVE, payload, sizeof (payload), &error))
          break;
        g_task_return_boolean (task, TRUE);
        return;
      }
    case WORK_ENROLL:
    case WORK_IDENTIFY:
      {
        struct interactive_result *result = capture_operation (self,
            work->operation == WORK_ENROLL, cancellable, &error);
        if (!result) break;
        g_task_return_pointer (task, result, g_free);
        return;
      }
    case WORK_CLEAR:
      {
        if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
          {
            g_autofree guint8 *body = g_malloc0 (44500);
            guint32 count;
            if (!set_group (self, GOODIX_QSEE_GROUP_DEFAULT, &error) ||
                !fingerpr_enumerate (self, body, &count, &error))
              break;
            if (count > 10)
              { g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                     "fingerpr returned too many templates"); break; }
            for (guint32 i = 0; i < count; i++)
              {
                guint32 finger;
                memcpy (&finger, body + 24500 + i * 400, 4);
                if (g_cancellable_is_cancelled (cancellable))
                  { g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                         "Clear storage cancelled"); break; }
                if (!fingerpr_remove (self, finger, &error)) break;
              }
            if (error) break;
            g_task_return_boolean (task, TRUE);
            return;
          }
        guint8 enumerate[GOODIX_QSEE_ENUMERATE_SIZE] = {0};
        struct goodix_qsee_finger fingers[GOODIX_QSEE_ENUMERATE_MAX];
        size_t count, i;
        if (!set_group (self, GOODIX_QSEE_GROUP_DEFAULT, &error) ||
            !invoke_success (self, CMD_ENUMERATE, enumerate, sizeof (enumerate), &error))
          break;
        count = goodix_qsee_parse_enumerate (enumerate, fingers, NULL);
        for (i = 0; i < count; i++)
          {
            guint8 remove[112];
            if (g_cancellable_is_cancelled (cancellable))
              { g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                     "Clear storage cancelled"); break; }
            goodix_qsee_build_finger_command (remove, sizeof (remove),
                                               fingers[i].group_id, fingers[i].finger_id);
            if (!invoke_success (self, CMD_REMOVE, remove, sizeof (remove), &error)) break;
          }
        if (error) break;
        g_task_return_boolean (task, TRUE);
        return;
      }
    }
  if (work->operation == WORK_OPEN)
    {
      goodix_qsee_qsee_close (&self->qsee);
      goodix_qsee_sensor_close (&self->sensor);
    }
  g_task_return_error (task, g_steal_pointer (&error));
}

static void
start_worker (FpiDeviceGoodixQsee *self, enum worker_operation operation,
              guint32 group, guint32 finger, GAsyncReadyCallback callback)
{
  g_autoptr(GTask) task = g_task_new (self,
      operation == WORK_OPEN || operation == WORK_CLOSE ? NULL :
      fpi_device_get_cancellable (FP_DEVICE (self)), callback, NULL);
  struct worker_data *work = g_new0 (struct worker_data, 1);
  work->operation = operation; work->group_id = group; work->finger_id = finger;
  g_task_set_task_data (task, work, g_free);
  g_task_run_in_thread (task, worker_thread);
}

static FpPrint *
make_print (FpiDeviceGoodixQsee *self, guint32 group, guint32 finger)
{
  FpPrint *print = fp_print_new (FP_DEVICE (self));
  GVariant *data = g_variant_new ("(uuu)", self->profile, group, finger);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", data, NULL);
  return print;
}

static gboolean
parse_print (FpPrint *print, guint32 *profile, guint32 *group, guint32 *finger)
{
  g_autoptr(GVariant) data = NULL;
  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("(uuu)"))) return FALSE;
  g_variant_get (data, "(uuu)", profile, group, finger);
  return TRUE;
}

static void open_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_open_complete (FP_DEVICE (o), g_steal_pointer (&e)); }
static void close_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_close_complete (FP_DEVICE (o), g_steal_pointer (&e)); }
static void delete_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_delete_complete (FP_DEVICE (o), g_steal_pointer (&e)); }
static void clear_done (GObject *o, GAsyncResult *r, gpointer unused)
{ g_autoptr(GError) e = NULL; (void) unused; g_task_propagate_boolean (G_TASK (r), &e); fpi_device_clear_storage_complete (FP_DEVICE (o), g_steal_pointer (&e)); }

static void
list_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpiDeviceGoodixQsee *self = FPI_DEVICE_GOODIXQSEE (object);
  g_autoptr(GError) error = NULL;
  g_autofree struct list_result *result = g_task_propagate_pointer (G_TASK (async_result), &error);
  GPtrArray *prints = NULL;
  size_t i;
  (void) unused;
  if (!result) { fpi_device_list_complete (FP_DEVICE (self), NULL, g_steal_pointer (&error)); return; }
  if (result->count_mismatch) fp_warn ("ENUMERATE count disagrees with occupied slots");
  prints = g_ptr_array_new_with_free_func (g_object_unref);
  for (i = 0; i < result->count; i++)
    g_ptr_array_add (prints, g_object_ref_sink (make_print (self,
                         result->fingers[i].group_id, result->fingers[i].finger_id)));
  fpi_device_list_complete (FP_DEVICE (self), prints, NULL);
}

static void
enroll_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpiDeviceGoodixQsee *self = FPI_DEVICE_GOODIXQSEE (object);
  g_autoptr(GError) error = NULL;
  g_autofree struct interactive_result *result = g_task_propagate_pointer (G_TASK (async_result), &error);
  FpPrint *print = NULL;
  GVariant *data;
  (void) unused;
  if (!result) { fpi_device_enroll_complete (FP_DEVICE (self), NULL, g_steal_pointer (&error)); return; }
  if (result->adopted_existing)
    fpi_device_enroll_progress (FP_DEVICE (self), ENROLL_STAGES_FINGERPR,
                                NULL, NULL);
  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  data = g_variant_new ("(uuu)", self->profile, result->group_id, result->finger_id);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", data, NULL);
  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

static void
identify_done (GObject *object, GAsyncResult *async_result, gpointer unused)
{
  FpiDeviceGoodixQsee *self = FPI_DEVICE_GOODIXQSEE (object);
  g_autoptr(GError) error = NULL;
  g_autofree struct interactive_result *result = g_task_propagate_pointer (G_TASK (async_result), &error);
  GPtrArray *gallery = NULL;
  FpPrint *match = NULL, *scan = NULL;
  guint i;
  (void) unused;
  if (!result) { fpi_device_identify_complete (FP_DEVICE (self), g_steal_pointer (&error)); return; }
  if (result->status && result->status != GOODIX_QSEE_MATCH_FAIL_AND_RETRY)
    {
      fpi_device_identify_report (FP_DEVICE (self), NULL, NULL,
                                  retry_for_status (result->status));
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
      return;
    }
  if (!result->status)
    {
      scan = g_object_ref_sink (make_print (self, result->group_id, result->finger_id));
      fpi_device_get_identify_data (FP_DEVICE (self), &gallery);
      for (i = 0; i < gallery->len; i++)
        {
          guint32 profile, group, finger;
          if (parse_print (g_ptr_array_index (gallery, i), &profile, &group, &finger) &&
              profile == self->profile && group == result->group_id &&
              finger == result->finger_id)
            { match = g_ptr_array_index (gallery, i); break; }
        }
    }
  fpi_device_identify_report (FP_DEVICE (self), match, scan, NULL);
  fpi_device_identify_complete (FP_DEVICE (self), NULL);
  g_clear_object (&scan);
}

static void goodix_open (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_OPEN, 0, 0, open_done); }
static void goodix_close (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_CLOSE, 0, 0, close_done); }
static void goodix_list (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_LIST, GOODIX_QSEE_GROUP_DEFAULT, 0, list_done); }
static void goodix_enroll (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_ENROLL, 0, 0, enroll_done); }
static void goodix_identify (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_IDENTIFY, 0, 0, identify_done); }
static void goodix_clear (FpDevice *d) { start_worker (FPI_DEVICE_GOODIXQSEE (d), WORK_CLEAR, 0, 0, clear_done); }

static void
goodix_delete (FpDevice *device)
{
  FpPrint *print = NULL; guint32 profile, group, finger;
  fpi_device_get_delete_data (device, &print);
  if (!parse_print (print, &profile, &group, &finger) ||
      profile != FPI_DEVICE_GOODIXQSEE (device)->profile)
    { fpi_device_delete_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID)); return; }
  start_worker (FPI_DEVICE_GOODIXQSEE (device), WORK_DELETE, group, finger, delete_done);
}

static void
goodix_cancel (FpDevice *device)
{
  /* The worker observes the action cancellable; interactive workers send
   * CMD_CANCEL before completing.  No second QSEE invoke races this thread. */
  (void) device;
}

static void
goodix_probe (FpDevice *device)
{
  FpiDeviceGoodixQsee *self = FPI_DEVICE_GOODIXQSEE (device);
  g_autoptr(GError) error = NULL;
  g_autofree gchar *device_id = NULL;

  self->profile = fpi_device_get_driver_data (device);
  if (self->profile == GOODIX_QSEE_PROFILE_FINGERPR)
    fpi_device_set_nr_enroll_stages (device, ENROLL_STAGES_FINGERPR);
  self->ta_name = read_ta_name (device, &error);
  if (self->ta_name)
    device_id = g_strdup_printf ("profile-%u:%s", self->profile, self->ta_name);
  fpi_device_probe_complete (device, device_id, NULL, g_steal_pointer (&error));
}

static void
fpi_device_goodixqsee_init (FpiDeviceGoodixQsee *self)
{
  self->sensor.device_fd = self->sensor.event_fd = -1;
  self->qsee.fd = -1;
  self->token_provider = goodix_qsee_challenge_token;
}

static void
fpi_device_goodixqsee_finalize (GObject *object)
{
  FpiDeviceGoodixQsee *self = FPI_DEVICE_GOODIXQSEE (object);
  g_clear_pointer (&self->ta_name, g_free);
  G_OBJECT_CLASS (fpi_device_goodixqsee_parent_class)->finalize (object);
}

static void
fpi_device_goodixqsee_class_init (FpiDeviceGoodixQseeClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *device_class = FP_DEVICE_CLASS (klass);
  object_class->finalize = fpi_device_goodixqsee_finalize;
  device_class->id = FP_COMPONENT;
  device_class->full_name = "Goodix QSEE match-on-chip sensor";
  device_class->type = FP_DEVICE_TYPE_UDEV;
  device_class->id_table = id_table;
  device_class->scan_type = FP_SCAN_TYPE_PRESS;
  device_class->nr_enroll_stages = ENROLL_STAGES_PROFILE_V1;
  device_class->temp_hot_seconds = -1;
  device_class->open = goodix_open;
  device_class->probe = goodix_probe;
  device_class->close = goodix_close;
  device_class->list = goodix_list;
  device_class->delete = goodix_delete;
  device_class->clear_storage = goodix_clear;
  device_class->enroll = goodix_enroll;
  device_class->identify = goodix_identify;
  device_class->cancel = goodix_cancel;
  fpi_device_class_auto_initialize_features (device_class);
}
