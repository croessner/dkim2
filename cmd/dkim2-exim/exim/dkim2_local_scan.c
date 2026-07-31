/*
 * Source-linked Exim local_scan adapter for the bounded DXI1 protocol.
 *
 * This file is compiled into one exact Exim source tree. It uses only the
 * documented local_scan API and system interfaces; it is not a shared plugin.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef LOCAL_SCAN
#define LOCAL_SCAN
#endif
#include "local_scan.h"

#include "build-id-v1.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/ucred.h>
#endif

#define DKIM2_FRAME_HEADER_BYTES 12U
#define DKIM2_REQUEST_PREFIX_BYTES 18U
#define DKIM2_BUILD_ID_BYTES 64U
#define DKIM2_REQUEST_PAYLOAD_MAX 34079124U
#define DKIM2_RESPONSE_PAYLOAD_MAX 69575U
#define DKIM2_MESSAGE_MAX 33554432U
#define DKIM2_HEADER_AGGREGATE_MAX 1048576U
#define DKIM2_HEADER_FIELD_MAX 65536U
#define DKIM2_RECIPIENT_MAX 2000U
#define DKIM2_HEADER_MAX 2000U
#define DKIM2_ENVELOPE_MAX 256U
#define DKIM2_PEER_MAX 64U
#define DKIM2_HELO_MAX 255U
#define DKIM2_PROTOCOL_MAX 32U
#define DKIM2_ADD_VALUE_MAX 65535U
#define DKIM2_LOCATOR_BYTES 32U

static const char dkim2_build_id[DKIM2_BUILD_ID_BYTES + 1U]
  __attribute__((used)) = DKIM2_EXIM_BUILD_ID_V1;

#define DKIM2_DECISION_ACCEPT 1U
#define DKIM2_DECISION_REJECT 2U
#define DKIM2_DECISION_TEMPFAIL 3U

#define DKIM2_REASON_NONE 0U
#define DKIM2_REASON_POLICY_REJECT 1U
#define DKIM2_REASON_SERVICE_UNAVAILABLE 2U
#define DKIM2_REASON_TIMEOUT 3U
#define DKIM2_REASON_INVALID_REQUEST 4U
#define DKIM2_REASON_FIDELITY 5U
#define DKIM2_REASON_CONTRACT 6U
#define DKIM2_REASON_RESOURCE 7U
#define DKIM2_REASON_INTERNAL 8U

#define DKIM2_ADD_NONE 0U
#define DKIM2_ADD_AUTHENTICATION_RESULTS 1U

static uschar *dkim2_failure_mode = US"tempfail";
static int dkim2_max_message_bytes = (int)DKIM2_MESSAGE_MAX;
static uschar *dkim2_socket;
static uschar *dkim2_spool_format;
static int dkim2_timeout = 11;

optionlist local_scan_options[] = {
  {
    .name = "dkim2_failure_mode",
    .type = opt_stringptr,
    .v.value = &dkim2_failure_mode,
  },
  {
    .name = "dkim2_max_message_bytes",
    .type = opt_int,
    .v.value = &dkim2_max_message_bytes,
  },
  {
    .name = "dkim2_socket",
    .type = opt_stringptr,
    .v.value = &dkim2_socket,
  },
  {
    .name = "dkim2_spool_format",
    .type = opt_stringptr,
    .v.value = &dkim2_spool_format,
  },
  {
    .name = "dkim2_timeout",
    .type = opt_time,
    .v.value = &dkim2_timeout,
  },
};

int local_scan_options_count =
  (int)(sizeof(local_scan_options) / sizeof(local_scan_options[0]));

struct dkim2_slice {
  const unsigned char *data;
  size_t length;
};

struct dkim2_request {
  unsigned char session;
  struct dkim2_slice peer;
  uint16_t peer_port;
  struct dkim2_slice helo;
  struct dkim2_slice protocol;
  struct dkim2_slice mail_from;
  struct dkim2_slice *recipients;
  uint16_t recipient_count;
  struct dkim2_slice *headers;
  uint16_t header_count;
  uint16_t *eligible_removals;
  uint16_t eligible_count;
  unsigned char *body;
  uint32_t body_length;
};

struct dkim2_response {
  uint8_t decision;
  uint8_t reason;
  uint16_t removal_count;
  const unsigned char *removals;
  uint16_t add_name;
  uint16_t add_value_length;
  const unsigned char *add_value;
  const unsigned char *locator;
};

enum dkim2_failure {
  DKIM2_FAILURE_CONFIG,
  DKIM2_FAILURE_FIDELITY,
  DKIM2_FAILURE_RESOURCE,
  DKIM2_FAILURE_TRANSPORT,
  DKIM2_FAILURE_TIMEOUT,
  DKIM2_FAILURE_CONTRACT,
  DKIM2_FAILURE_INTERNAL
};

/* dkim2_u16 stores one canonical network-order integer. */
static void
dkim2_u16(unsigned char *output, uint16_t value)
{
  output[0] = (unsigned char)(value >> 8);
  output[1] = (unsigned char)value;
}

/* dkim2_u32 stores one canonical network-order integer. */
static void
dkim2_u32(unsigned char *output, uint32_t value)
{
  output[0] = (unsigned char)(value >> 24);
  output[1] = (unsigned char)(value >> 16);
  output[2] = (unsigned char)(value >> 8);
  output[3] = (unsigned char)value;
}

/* dkim2_read_u16 loads one canonical network-order integer. */
static uint16_t
dkim2_read_u16(const unsigned char *input)
{
  return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

/* dkim2_read_u32 loads one canonical network-order integer. */
static uint32_t
dkim2_read_u32(const unsigned char *input)
{
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
    ((uint32_t)input[2] << 8) | input[3];
}

/* dkim2_add_size performs overflow-safe aggregate accounting. */
static int
dkim2_add_size(size_t *total, size_t value, size_t maximum)
{
  if (value > maximum || *total > maximum - value)
    return 0;
  *total += value;
  return 1;
}

/* dkim2_bounded_cstring admits one NUL-terminated public-ABI scalar. */
static int
dkim2_bounded_cstring(
  const uschar *value,
  size_t maximum,
  int allow_empty,
  struct dkim2_slice *output)
{
  size_t length;

  if (!value)
    {
    if (!allow_empty)
      return 0;
    output->data = NULL;
    output->length = 0;
    return 1;
    }
  length = strnlen(CCS value, maximum + 1U);
  if (length > maximum || (!allow_empty && length == 0U) ||
      memchr(value, '\r', length) || memchr(value, '\n', length))
    return 0;
  output->data = value;
  output->length = length;
  return 1;
}

/* dkim2_valid_header validates Exim's exact LF field representation. */
static int
dkim2_valid_header(const header_line *header)
{
  int index;

  if (!header || !header->text || header->slen <= 0 ||
      header->slen > (int)DKIM2_HEADER_FIELD_MAX ||
      header->text[header->slen - 1] != '\n' ||
      memchr(header->text, '\0', (size_t)header->slen) ||
      memchr(header->text, '\r', (size_t)header->slen))
    return 0;
  for (index = 0; index + 1 < header->slen; index++)
    if (header->text[index] == '\n' &&
        header->text[index + 1] != ' ' &&
        header->text[index + 1] != '\t')
      return 0;
  return 1;
}

/* dkim2_free_request releases only adapter-owned temporary storage. */
static void
dkim2_free_request(struct dkim2_request *request)
{
  if (!request)
    return;
  if (request->body && request->body_length)
    memset(request->body, 0, request->body_length);
  free(request->body);
  free(request->recipients);
  free(request->headers);
  free(request->eligible_removals);
  memset(request, 0, sizeof(*request));
}

/* dkim2_observe_headers captures non-deleted fields in original order. */
static int
dkim2_observe_headers(
  struct dkim2_request *request,
  size_t *header_bytes)
{
  header_line *header;
  uint16_t count = 0;
  uint16_t eligible = 0;
  size_t aggregate = 0;

  for (header = header_list; header; header = header->next)
    if (header->type != '*')
      {
      if (count == DKIM2_HEADER_MAX || !dkim2_valid_header(header) ||
          !dkim2_add_size(&aggregate, (size_t)header->slen,
            DKIM2_HEADER_AGGREGATE_MAX))
        return 0;
      count++;
      if (header_testname(header, US"Authentication-Results", 22, TRUE))
        eligible++;
      }
  if (count)
    {
    request->headers = calloc(count, sizeof(*request->headers));
    if (!request->headers)
      return 0;
    }
  if (eligible)
    {
    request->eligible_removals =
      calloc(eligible, sizeof(*request->eligible_removals));
    if (!request->eligible_removals)
      return 0;
    }
  request->header_count = count;
  request->eligible_count = eligible;
  count = 0;
  eligible = 0;
  for (header = header_list; header; header = header->next)
    if (header->type != '*')
      {
      if (!request->headers || count >= request->header_count)
        return 0;
      request->headers[count].data = header->text;
      request->headers[count].length = (size_t)header->slen;
      count++;
      if (header_testname(header, US"Authentication-Results", 22, TRUE))
        {
        if (!request->eligible_removals || eligible >= request->eligible_count)
          return 0;
        request->eligible_removals[eligible] = (uint16_t)(eligible + 1U);
        eligible++;
        }
      }
  if (count != request->header_count || eligible != request->eligible_count)
    return 0;
  *header_bytes = aggregate;
  return 1;
}

/* dkim2_observe_recipients captures the ordered receive-time envelope. */
static int
dkim2_observe_recipients(struct dkim2_request *request)
{
  int index;

  if (recipients_count < 1 || recipients_count > (int)DKIM2_RECIPIENT_MAX ||
      !recipients_list)
    return 0;
  request->recipients =
    calloc((size_t)recipients_count, sizeof(*request->recipients));
  if (!request->recipients)
    return 0;
  for (index = 0; index < recipients_count; index++)
    if (!dkim2_bounded_cstring(
          recipients_list[index].address,
          DKIM2_ENVELOPE_MAX,
          0,
          &request->recipients[index]))
      return 0;
  request->recipient_count = (uint16_t)recipients_count;
  return 1;
}

/* dkim2_read_body reads exact Exim spool bytes and restores the body offset. */
static int
dkim2_read_body(
  int fd,
  size_t header_bytes,
  struct dkim2_request *request,
  enum dkim2_failure *failure)
{
  struct stat status;
  off_t body_offset = (off_t)SPOOL_DATA_START_OFFSET;
  off_t body_size;
  size_t offset = 0;

  if (fd < 0 || fstat(fd, &status) < 0 || !S_ISREG(status.st_mode) ||
      status.st_size < body_offset)
    {
    *failure = DKIM2_FAILURE_FIDELITY;
    return 0;
    }
  body_size = status.st_size - body_offset;
  if (body_size < 0 || (uintmax_t)body_size > UINT32_MAX ||
      (uintmax_t)body_size > (uintmax_t)dkim2_max_message_bytes ||
      header_bytes + 1U > (size_t)dkim2_max_message_bytes ||
      (uintmax_t)body_size >
        (uintmax_t)((size_t)dkim2_max_message_bytes - header_bytes - 1U))
    {
    *failure = DKIM2_FAILURE_RESOURCE;
    return 0;
    }
  if (lseek(fd, body_offset, SEEK_SET) != body_offset)
    {
    *failure = DKIM2_FAILURE_FIDELITY;
    return 0;
    }
  if (body_size)
    {
    request->body = malloc((size_t)body_size);
    if (!request->body)
      {
      *failure = DKIM2_FAILURE_RESOURCE;
      (void)lseek(fd, body_offset, SEEK_SET);
      return 0;
      }
    while (offset < (size_t)body_size)
      {
      ssize_t count = read(fd, request->body + offset, (size_t)body_size - offset);
      if (count < 0 && errno == EINTR)
        continue;
      if (count <= 0)
        {
        *failure = DKIM2_FAILURE_FIDELITY;
        (void)lseek(fd, body_offset, SEEK_SET);
        return 0;
        }
      offset += (size_t)count;
      }
    }
  request->body_length = (uint32_t)body_size;
  if (lseek(fd, body_offset, SEEK_SET) != body_offset)
    {
    *failure = DKIM2_FAILURE_FIDELITY;
    return 0;
    }
  return 1;
}

/* dkim2_observe_request validates and captures the documented Exim ABI. */
static int
dkim2_observe_request(
  int fd,
  struct dkim2_request *request,
  enum dkim2_failure *failure)
{
  size_t header_bytes = 0;
  const uschar *helo = NULL;

  if (!dkim2_spool_format ||
      strcmp(CCS dkim2_spool_format, "unix_lf") != 0)
    {
    *failure = DKIM2_FAILURE_CONFIG;
    return 0;
    }
  if (!dkim2_socket || dkim2_socket[0] != '/' ||
      strnlen(CCS dkim2_socket, sizeof(((struct sockaddr_un *)0)->sun_path))
        >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
      dkim2_timeout < 1 || dkim2_timeout > 11 ||
      dkim2_max_message_bytes < 1 ||
      dkim2_max_message_bytes > (int)DKIM2_MESSAGE_MAX ||
      !dkim2_failure_mode ||
      strcmp(CCS dkim2_failure_mode, "tempfail") != 0)
    {
    *failure = DKIM2_FAILURE_CONFIG;
    return 0;
    }
  request->session = smtp_batched_input ? 2U : (smtp_input ? 1U : 0U);
  if (!dkim2_bounded_cstring(
        sender_host_address,
        DKIM2_PEER_MAX,
        1,
        &request->peer) ||
      sender_host_port < 0 || sender_host_port > UINT16_MAX ||
      ((request->peer.length == 0U) != (sender_host_port == 0)))
    {
    *failure = DKIM2_FAILURE_FIDELITY;
    return 0;
    }
  request->peer_port = (uint16_t)sender_host_port;
  if (request->session != 0U)
    {
    helo = expand_string(US"$sender_helo_name");
    if (!helo)
      {
      *failure = DKIM2_FAILURE_FIDELITY;
      return 0;
      }
    }
  if (!dkim2_bounded_cstring(helo, DKIM2_HELO_MAX, 1, &request->helo) ||
      !dkim2_bounded_cstring(
        received_protocol,
        DKIM2_PROTOCOL_MAX,
        1,
        &request->protocol) ||
      !dkim2_bounded_cstring(
        sender_address,
        DKIM2_ENVELOPE_MAX,
        1,
        &request->mail_from) ||
      !dkim2_observe_recipients(request) ||
      !dkim2_observe_headers(request, &header_bytes))
    {
    *failure = DKIM2_FAILURE_FIDELITY;
    return 0;
    }
  return dkim2_read_body(fd, header_bytes, request, failure);
}

/* dkim2_request_length computes the exact bounded positional payload size. */
static int
dkim2_request_length(const struct dkim2_request *request, size_t *output)
{
  size_t length = DKIM2_REQUEST_PREFIX_BYTES + DKIM2_BUILD_ID_BYTES + 4U;
  uint16_t index;

  if (!dkim2_add_size(&length, request->peer.length, DKIM2_REQUEST_PAYLOAD_MAX) ||
      !dkim2_add_size(&length, request->helo.length, DKIM2_REQUEST_PAYLOAD_MAX) ||
      !dkim2_add_size(
        &length, request->protocol.length, DKIM2_REQUEST_PAYLOAD_MAX) ||
      !dkim2_add_size(
        &length, request->mail_from.length, DKIM2_REQUEST_PAYLOAD_MAX))
    return 0;
  for (index = 0; index < request->recipient_count; index++)
    if (!dkim2_add_size(
          &length, 2U + request->recipients[index].length,
          DKIM2_REQUEST_PAYLOAD_MAX))
      return 0;
  for (index = 0; index < request->header_count; index++)
    if (!dkim2_add_size(
          &length, 4U + request->headers[index].length,
          DKIM2_REQUEST_PAYLOAD_MAX))
      return 0;
  if (!dkim2_add_size(
        &length, request->body_length, DKIM2_REQUEST_PAYLOAD_MAX))
    return 0;
  *output = length;
  return 1;
}

/* dkim2_encode_request serializes one complete canonical DXI1 request. */
static unsigned char *
dkim2_encode_request(const struct dkim2_request *request, size_t *frame_length)
{
  unsigned char *frame;
  unsigned char *cursor;
  size_t payload_length;
  uint16_t index;

  if (!dkim2_request_length(request, &payload_length))
    return NULL;
  frame = malloc(DKIM2_FRAME_HEADER_BYTES + payload_length);
  if (!frame)
    return NULL;
  memcpy(frame, "DXI1", 4U);
  frame[4] = 1U;
  frame[5] = 1U;
  frame[6] = 0U;
  frame[7] = 0U;
  dkim2_u32(frame + 8U, (uint32_t)payload_length);
  cursor = frame + DKIM2_FRAME_HEADER_BYTES;
  dkim2_u16(cursor, DKIM2_BUILD_ID_BYTES);
  cursor[2] = 1U;
  cursor[3] = request->session;
  dkim2_u16(cursor + 4U, request->recipient_count);
  dkim2_u16(cursor + 6U, request->header_count);
  dkim2_u16(cursor + 8U, (uint16_t)request->peer.length);
  dkim2_u16(cursor + 10U, request->peer_port);
  dkim2_u16(cursor + 12U, (uint16_t)request->helo.length);
  dkim2_u16(cursor + 14U, (uint16_t)request->protocol.length);
  dkim2_u16(cursor + 16U, (uint16_t)request->mail_from.length);
  cursor += DKIM2_REQUEST_PREFIX_BYTES;
#define DKIM2_COPY_SLICE(value) \
  do { \
    if ((value).length) \
      memcpy(cursor, (value).data, (value).length); \
    cursor += (value).length; \
  } while (0)
  memcpy(cursor, dkim2_build_id, DKIM2_BUILD_ID_BYTES);
  cursor += DKIM2_BUILD_ID_BYTES;
  DKIM2_COPY_SLICE(request->peer);
  DKIM2_COPY_SLICE(request->helo);
  DKIM2_COPY_SLICE(request->protocol);
  DKIM2_COPY_SLICE(request->mail_from);
  for (index = 0; index < request->recipient_count; index++)
    {
    dkim2_u16(cursor, (uint16_t)request->recipients[index].length);
    cursor += 2U;
    DKIM2_COPY_SLICE(request->recipients[index]);
    }
  for (index = 0; index < request->header_count; index++)
    {
    dkim2_u32(cursor, (uint32_t)request->headers[index].length);
    cursor += 4U;
    DKIM2_COPY_SLICE(request->headers[index]);
    }
#undef DKIM2_COPY_SLICE
  dkim2_u32(cursor, request->body_length);
  cursor += 4U;
  if (request->body_length)
    memcpy(cursor, request->body, request->body_length);
  cursor += request->body_length;
  if ((size_t)(cursor - frame) != DKIM2_FRAME_HEADER_BYTES + payload_length)
    {
    free(frame);
    return NULL;
    }
  *frame_length = (size_t)(cursor - frame);
  return frame;
}

/* dkim2_monotonic_milliseconds returns a monotonic deadline clock. */
static int64_t
dkim2_monotonic_milliseconds(void)
{
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
    return -1;
  if ((uintmax_t)now.tv_sec > (uintmax_t)INT64_MAX / 1000U)
    return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* dkim2_remaining_milliseconds bounds one operation by an absolute deadline. */
static int
dkim2_remaining_milliseconds(int64_t deadline, int *remaining)
{
  int64_t now = dkim2_monotonic_milliseconds();
  int64_t available;

  if (now < 0 || deadline <= now)
    return 0;
  available = deadline - now;
  *remaining = available > INT_MAX ? INT_MAX : (int)available;
  return *remaining > 0;
}

/* dkim2_wait_socket waits for one event within the aggregate IPC deadline. */
static int
dkim2_wait_socket(int fd, short events, int64_t deadline)
{
  struct pollfd descriptor;
  int remaining;
  int result;

  descriptor.fd = fd;
  descriptor.events = events;
  descriptor.revents = 0;
  do
    {
    if (!dkim2_remaining_milliseconds(deadline, &remaining))
      return 0;
    result = poll(&descriptor, 1U, remaining);
    }
  while (result < 0 && errno == EINTR);
  if (result <= 0)
    return 0;
  return (descriptor.revents & events) != 0 &&
    (descriptor.revents & (POLLERR | POLLNVAL)) == 0;
}

/* dkim2_check_socket_path verifies stable same-UID socket authority. */
static int
dkim2_check_socket_path(const struct stat *before)
{
  struct stat after;

  if (stat(CCS dkim2_socket, &after) < 0 || !S_ISSOCK(after.st_mode) ||
      after.st_uid != geteuid() || (after.st_mode & 0777) != 0600)
    return 0;
  if (before &&
      (before->st_dev != after.st_dev || before->st_ino != after.st_ino))
    return 0;
  return 1;
}

/* dkim2_check_peer_uid admits only a server with Exim's effective UID. */
static int
dkim2_check_peer_uid(int fd)
{
#if defined(__linux__)
  struct ucred credential;
  socklen_t length = (socklen_t)sizeof(credential);

  memset(&credential, 0, sizeof(credential));
  return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credential, &length) == 0 &&
    length == sizeof(credential) && credential.uid == geteuid();
#elif defined(__APPLE__) || defined(__FreeBSD__)
  uid_t uid;
  gid_t gid;

  return getpeereid(fd, &uid, &gid) == 0 && uid == geteuid();
#else
  (void)fd;
  return 0;
#endif
}

/* dkim2_connect opens one bounded same-UID AF_UNIX connection. */
static int
dkim2_connect(enum dkim2_failure *failure, int64_t deadline)
{
  struct sockaddr_un address;
  struct stat path_status;
  int fd;
  int flags;
  int no_sigpipe = 1;
  int socket_error = 0;
  socklen_t address_length;
  socklen_t socket_error_length = (socklen_t)sizeof(socket_error);

  if (!dkim2_check_socket_path(NULL) ||
      stat(CCS dkim2_socket, &path_status) < 0)
    {
    *failure = DKIM2_FAILURE_TRANSPORT;
    return -1;
    }
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
    *failure = DKIM2_FAILURE_TRANSPORT;
    return -1;
    }
#ifdef SO_NOSIGPIPE
  if (setsockopt(
        fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) < 0)
    goto transport_failure;
#else
  (void)no_sigpipe;
#endif
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    goto transport_failure;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, dkim2_socket, strlen(CCS dkim2_socket) + 1U);
#if defined(__APPLE__) || defined(__FreeBSD__)
  address.sun_len = (unsigned char)(
    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1U);
#endif
  address_length = (socklen_t)(
    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1U);
  if (connect(fd, (struct sockaddr *)&address, address_length) < 0)
    {
    if (errno != EINPROGRESS)
      goto transport_failure;
    if (!dkim2_wait_socket(fd, POLLOUT, deadline))
      {
      *failure = DKIM2_FAILURE_TIMEOUT;
      close(fd);
      return -1;
      }
    if (getsockopt(
          fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_length) < 0 ||
        socket_error != 0)
      goto transport_failure;
    }
  if (!dkim2_check_socket_path(&path_status) ||
      !dkim2_check_peer_uid(fd))
    goto transport_failure;
  return fd;

transport_failure:
  *failure = DKIM2_FAILURE_TRANSPORT;
  close(fd);
  return -1;
}

/* dkim2_write_all sends one frame without retrying an authoritative request. */
static int
dkim2_write_all(
  int fd,
  const unsigned char *data,
  size_t length,
  int64_t deadline)
{
  size_t offset = 0;
  int flags = 0;

#ifdef MSG_NOSIGNAL
  flags = MSG_NOSIGNAL;
#endif

  while (offset < length)
    {
    if (!dkim2_wait_socket(fd, POLLOUT, deadline))
      {
      errno = EAGAIN;
      return 0;
      }
    ssize_t count = send(fd, data + offset, length - offset, flags);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (count == 0)
      {
      errno = ECONNRESET;
      return 0;
      }
    if (count < 0)
      return 0;
    offset += (size_t)count;
    }
  return 1;
}

/* dkim2_read_all receives one declared byte sequence or fails closed. */
static int
dkim2_read_all(int fd, unsigned char *data, size_t length, int64_t deadline)
{
  size_t offset = 0;

  while (offset < length)
    {
    if (!dkim2_wait_socket(fd, POLLIN, deadline))
      {
      errno = EAGAIN;
      return 0;
      }
    ssize_t count = read(fd, data + offset, length - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (count == 0)
      {
      errno = ECONNRESET;
      return 0;
      }
    if (count < 0)
      return 0;
    offset += (size_t)count;
    }
  return 1;
}

/* dkim2_exchange performs exactly one request and one EOF-delimited response. */
static unsigned char *
dkim2_exchange(
  const unsigned char *request,
  size_t request_length,
  size_t *response_length,
  enum dkim2_failure *failure)
{
  unsigned char header[DKIM2_FRAME_HEADER_BYTES];
  unsigned char trailing;
  unsigned char *frame = NULL;
  uint32_t payload_length;
  int64_t now = dkim2_monotonic_milliseconds();
  int64_t deadline;
  int fd;
  ssize_t count;

  if (now < 0 || now > INT64_MAX - (int64_t)dkim2_timeout * 1000)
    {
    *failure = DKIM2_FAILURE_TIMEOUT;
    return NULL;
    }
  deadline = now + (int64_t)dkim2_timeout * 1000;
  fd = dkim2_connect(failure, deadline);
  if (fd < 0)
    return NULL;
  if (!dkim2_write_all(fd, request, request_length, deadline) ||
      shutdown(fd, SHUT_WR) < 0 ||
      !dkim2_read_all(fd, header, sizeof(header), deadline))
    goto transport_failure;
  if (memcmp(header, "DXI1", 4U) != 0 || header[4] != 1U ||
      header[5] != 2U || header[6] != 0U || header[7] != 0U)
    goto contract_failure;
  payload_length = dkim2_read_u32(header + 8U);
  if (payload_length < 8U || payload_length > DKIM2_RESPONSE_PAYLOAD_MAX)
    goto contract_failure;
  frame = malloc(DKIM2_FRAME_HEADER_BYTES + payload_length);
  if (!frame)
    {
    *failure = DKIM2_FAILURE_RESOURCE;
    close(fd);
    return NULL;
    }
  memcpy(frame, header, sizeof(header));
  if (!dkim2_read_all(
        fd, frame + sizeof(header), payload_length, deadline))
    goto transport_failure;
  if (!dkim2_wait_socket(fd, POLLIN, deadline))
    goto transport_failure;
  do
    count = read(fd, &trailing, 1U);
  while (count < 0 && errno == EINTR);
  if (count != 0)
    goto contract_failure;
  close(fd);
  *response_length = DKIM2_FRAME_HEADER_BYTES + payload_length;
  return frame;

contract_failure:
  *failure = DKIM2_FAILURE_CONTRACT;
  free(frame);
  close(fd);
  return NULL;

transport_failure:
  *failure = errno == EAGAIN || errno == EWOULDBLOCK
    ? DKIM2_FAILURE_TIMEOUT : DKIM2_FAILURE_TRANSPORT;
  free(frame);
  close(fd);
  return NULL;
}

/* dkim2_valid_locator validates exact unpadded base64url spelling. */
static int
dkim2_valid_locator(const unsigned char *value)
{
  size_t index;

  for (index = 0; index < DKIM2_LOCATOR_BYTES; index++)
    if (!((value[index] >= 'A' && value[index] <= 'Z') ||
          (value[index] >= 'a' && value[index] <= 'z') ||
          (value[index] >= '0' && value[index] <= '9') ||
          value[index] == '-' || value[index] == '_'))
      return 0;
  return 1;
}

/* dkim2_eligible_removal verifies one original RFC 8601 occurrence. */
static int
dkim2_eligible_removal(
  const struct dkim2_request *request,
  uint16_t occurrence)
{
  uint16_t index;

  for (index = 0; index < request->eligible_count; index++)
    if (request->eligible_removals[index] == occurrence)
      return 1;
  return 0;
}

/* dkim2_decode_response prevalidates every decision and action before mutation. */
static int
dkim2_decode_response(
  const unsigned char *frame,
  size_t frame_length,
  const struct dkim2_request *request,
  struct dkim2_response *response)
{
  const unsigned char *payload;
  size_t payload_length;
  size_t required;
  size_t trailing;
  uint16_t index;
  uint16_t previous = UINT16_MAX;

  if (!frame || frame_length < DKIM2_FRAME_HEADER_BYTES + 8U ||
      memcmp(frame, "DXI1", 4U) != 0 || frame[4] != 1U ||
      frame[5] != 2U || frame[6] != 0U || frame[7] != 0U)
    return 0;
  payload_length = dkim2_read_u32(frame + 8U);
  if (payload_length > DKIM2_RESPONSE_PAYLOAD_MAX ||
      frame_length != DKIM2_FRAME_HEADER_BYTES + payload_length)
    return 0;
  payload = frame + DKIM2_FRAME_HEADER_BYTES;
  response->decision = payload[0];
  response->reason = payload[1];
  response->removal_count = dkim2_read_u16(payload + 2U);
  response->add_name = dkim2_read_u16(payload + 4U);
  response->add_value_length = dkim2_read_u16(payload + 6U);
  if (response->removal_count > DKIM2_HEADER_MAX ||
      response->removal_count > request->header_count ||
      response->removal_count > request->eligible_count)
    return 0;
  required = 8U + 2U * response->removal_count +
    response->add_value_length;
  if (required > payload_length)
    return 0;
  trailing = payload_length - required;
  if (trailing != 0U && trailing != DKIM2_LOCATOR_BYTES)
    return 0;
  response->removals = payload + 8U;
  response->add_value = response->removals + 2U * response->removal_count;
  response->locator =
    trailing == DKIM2_LOCATOR_BYTES
      ? response->add_value + response->add_value_length : NULL;
  if ((response->decision == DKIM2_DECISION_ACCEPT &&
       response->reason != DKIM2_REASON_NONE) ||
      (response->decision == DKIM2_DECISION_REJECT &&
       response->reason != DKIM2_REASON_POLICY_REJECT) ||
      (response->decision == DKIM2_DECISION_TEMPFAIL &&
       (response->reason < DKIM2_REASON_SERVICE_UNAVAILABLE ||
        response->reason > DKIM2_REASON_INTERNAL)) ||
      (response->decision != DKIM2_DECISION_ACCEPT &&
       response->decision != DKIM2_DECISION_REJECT &&
       response->decision != DKIM2_DECISION_TEMPFAIL))
    return 0;
  if (response->decision != DKIM2_DECISION_ACCEPT &&
      (response->removal_count != 0U ||
       response->add_name != DKIM2_ADD_NONE ||
       response->add_value_length != 0U || response->locator))
    return 0;
  if ((response->add_name == DKIM2_ADD_NONE &&
       response->add_value_length != 0U) ||
      (response->add_name == DKIM2_ADD_AUTHENTICATION_RESULTS &&
       response->add_value_length == 0U) ||
      (response->add_name != DKIM2_ADD_NONE &&
       response->add_name != DKIM2_ADD_AUTHENTICATION_RESULTS))
    return 0;
  if (response->add_value_length &&
      (memchr(response->add_value, '\0', response->add_value_length) ||
       memchr(response->add_value, '\r', response->add_value_length) ||
       memchr(response->add_value, '\n', response->add_value_length)))
    return 0;
  if (response->locator &&
      (response->decision != DKIM2_DECISION_ACCEPT ||
       !dkim2_valid_locator(response->locator)))
    return 0;
  for (index = 0; index < response->removal_count; index++)
    {
    uint16_t occurrence = dkim2_read_u16(response->removals + 2U * index);
    if (occurrence == 0U || occurrence >= previous ||
        !dkim2_eligible_removal(request, occurrence))
      return 0;
    previous = occurrence;
    }
  return 1;
}

/* dkim2_store_text copies bounded return data into Exim's permanent pool. */
static uschar *
dkim2_store_text(const unsigned char *value, size_t length)
{
  uschar *copy;

  if (length > (size_t)INT_MAX - 1U)
    return NULL;
  copy = store_get_perm_3(
    (int)(length + 1U),
    value ? value : GET_UNTAINTED,
    __func__,
    __LINE__);
  if (!copy)
    return NULL;
  if (length)
    memcpy(copy, value, length);
  copy[length] = '\0';
  return copy;
}

/* dkim2_apply_response applies a fully admitted response in closed order. */
static int
dkim2_apply_response(
  const struct dkim2_response *response,
  uschar **return_text)
{
  uint16_t index;
  char *add_value = NULL;

  if (response->add_name == DKIM2_ADD_AUTHENTICATION_RESULTS)
    {
    add_value = malloc((size_t)response->add_value_length + 1U);
    if (!add_value)
      return 0;
    memcpy(add_value, response->add_value, response->add_value_length);
    add_value[response->add_value_length] = '\0';
    }
  if (response->locator)
    {
    *return_text = dkim2_store_text(response->locator, DKIM2_LOCATOR_BYTES);
    if (!*return_text)
      {
      free(add_value);
      return 0;
      }
    }
  else
    *return_text = NULL;
  for (index = 0; index < response->removal_count; index++)
    header_remove(
      dkim2_read_u16(response->removals + 2U * index),
      US"Authentication-Results");
  if (add_value)
    {
    header_add_at_position(
      FALSE,
      NULL,
      TRUE,
      ' ',
      "Authentication-Results:%s\n",
      add_value);
    memset(add_value, 0, response->add_value_length);
    free(add_value);
    }
  return 1;
}

/* dkim2_log_failure emits only one closed local reason class. */
static void
dkim2_log_failure(enum dkim2_failure failure)
{
  static const char *const names[] = {
    "config", "fidelity", "resource", "transport", "timeout", "contract",
    "internal",
  };
  unsigned int index = (unsigned int)failure;

  if (index >= sizeof(names) / sizeof(names[0]))
    index = (unsigned int)DKIM2_FAILURE_INTERNAL;
  log_write(0, LOG_MAIN, "dkim2 local_scan failure class=%s", names[index]);
}

/* dkim2_fixed_return installs one local, content-free Exim reply. */
static int
dkim2_fixed_return(uschar **return_text, int reject)
{
  static const unsigned char reject_text[] =
    "DKIM2 policy rejected the message";
  static const unsigned char tempfail_text[] =
    "DKIM2 service temporarily unavailable";
  const unsigned char *value = reject ? reject_text : tempfail_text;
  size_t length = reject ? sizeof(reject_text) - 1U : sizeof(tempfail_text) - 1U;

  *return_text = dkim2_store_text(value, length);
  return reject ? LOCAL_SCAN_REJECT_NOLOGHDR : LOCAL_SCAN_TEMPREJECT_NOLOGHDR;
}

/* local_scan observes one Exim message and applies one closed DXI1 response. */
int
local_scan(int fd, uschar **return_text)
{
  struct dkim2_request request;
  struct dkim2_response response;
  enum dkim2_failure failure = DKIM2_FAILURE_INTERNAL;
  unsigned char *request_frame = NULL;
  unsigned char *response_frame = NULL;
  size_t request_length = 0;
  size_t response_length = 0;
  int result;

  if (!return_text)
    return LOCAL_SCAN_TEMPREJECT_NOLOGHDR;
  *return_text = NULL;
  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));
  if (!dkim2_observe_request(fd, &request, &failure))
    goto fail;
  request_frame = dkim2_encode_request(&request, &request_length);
  if (!request_frame)
    {
    failure = DKIM2_FAILURE_RESOURCE;
    goto fail;
    }
  response_frame = dkim2_exchange(
    request_frame, request_length, &response_length, &failure);
  if (!response_frame)
    goto fail;
  if (!dkim2_decode_response(
        response_frame, response_length, &request, &response))
    {
    failure = DKIM2_FAILURE_CONTRACT;
    goto fail;
    }
  if (response.decision == DKIM2_DECISION_ACCEPT)
    {
    if (!dkim2_apply_response(&response, return_text))
      {
      failure = DKIM2_FAILURE_RESOURCE;
      goto fail;
      }
    result = LOCAL_SCAN_ACCEPT;
    }
  else if (response.decision == DKIM2_DECISION_REJECT)
    result = dkim2_fixed_return(return_text, 1);
  else
    result = dkim2_fixed_return(return_text, 0);
  if (request_frame)
    memset(request_frame, 0, request_length);
  if (response_frame)
    memset(response_frame, 0, response_length);
  free(request_frame);
  free(response_frame);
  dkim2_free_request(&request);
  return result;

fail:
  dkim2_log_failure(failure);
  if (request_frame)
    memset(request_frame, 0, request_length);
  if (response_frame)
    memset(response_frame, 0, response_length);
  free(request_frame);
  free(response_frame);
  dkim2_free_request(&request);
  return dkim2_fixed_return(return_text, 0);
}
