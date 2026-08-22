/*
 * Independent public-ABI harness for the production local_scan function.
 *
 * The harness implements only documented Exim globals/functions and an
 * independent DXI1 peer. It does not include or reuse the Go codec.
 */

#ifndef LOCAL_SCAN
#define LOCAL_SCAN
#endif
#include "local_scan.h"

#include "build-id-v1.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define HARNESS_FRAME_HEADER 12U
#define HARNESS_BUILD_ID 64U
#define HARNESS_BODY_OFFSET SPOOL_DATA_START_OFFSET

extern optionlist local_scan_options[];
extern int local_scan_options_count;

unsigned int debug_selector;
int body_linecount;
int body_zerocount;
uschar *expand_string_message;
const uschar *headers_charset;
header_line *header_last;
header_line *header_list;
BOOL host_checking;
uschar *interface_address;
int interface_port;
uschar *message_id;
uschar *received_protocol;
int recipients_count;
recipient_item *recipients_list;
const unsigned char *sender_address;
uschar *sender_host_address;
uschar *sender_host_authenticated;
uschar *sender_host_name;
int sender_host_port;
BOOL smtp_batched_input;
BOOL smtp_input;
void *store_last_get[1];
int store_pool;

static uschar harness_helo[] = "helo.example";
static int harness_failures;
static int harness_log_count;
static int harness_socket_blocked;

struct harness_peer {
  int listener;
  unsigned char response[512];
  size_t response_length;
  int request_valid;
};

/* harness_fail records one content-free assertion failure. */
static void
harness_fail(const char *condition, int line)
{
  fprintf(stderr, "local_scan harness assertion failed at line %d: %s\n",
    line, condition);
  harness_failures++;
}

#define HARNESS_ASSERT(value) \
  do { \
    if (!(value)) \
      harness_fail(#value, __LINE__); \
  } while (0)

/* harness_read_u16 decodes one independent network-order integer. */
static uint16_t
harness_read_u16(const unsigned char *input)
{
  return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

/* harness_read_u32 decodes one independent network-order integer. */
static uint32_t
harness_read_u32(const unsigned char *input)
{
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
    ((uint32_t)input[2] << 8) | input[3];
}

/* harness_write_u16 encodes one independent network-order integer. */
static void
harness_write_u16(unsigned char *output, uint16_t value)
{
  output[0] = (unsigned char)(value >> 8);
  output[1] = (unsigned char)value;
}

/* harness_write_u32 encodes one independent network-order integer. */
static void
harness_write_u32(unsigned char *output, uint32_t value)
{
  output[0] = (unsigned char)(value >> 24);
  output[1] = (unsigned char)(value >> 16);
  output[2] = (unsigned char)(value >> 8);
  output[3] = (unsigned char)value;
}

/* harness_read_all receives an exact peer-owned byte sequence. */
static int
harness_read_all(int fd, unsigned char *output, size_t length)
{
  size_t offset = 0;

  while (offset < length)
    {
    ssize_t count = read(fd, output + offset, length - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return 0;
    offset += (size_t)count;
    }
  return 1;
}

/* harness_write_all sends an exact peer-owned byte sequence. */
static int
harness_write_all(int fd, const unsigned char *input, size_t length)
{
  size_t offset = 0;

  while (offset < length)
    {
    ssize_t count = write(fd, input + offset, length - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return 0;
    offset += (size_t)count;
    }
  return 1;
}

/* harness_consume_slice validates and advances one independent request cursor. */
static int
harness_consume_slice(
  const unsigned char **cursor,
  const unsigned char *end,
  const unsigned char *expected,
  size_t length)
{
  if ((size_t)(end - *cursor) < length ||
      (length && memcmp(*cursor, expected, length) != 0))
    return 0;
  *cursor += length;
  return 1;
}

/* harness_validate_request independently admits the canonical test request. */
static int
harness_validate_request(const unsigned char *frame, size_t frame_length)
{
  static const unsigned char peer[] = "192.0.2.10";
  static const unsigned char helo[] = "helo.example";
  static const unsigned char protocol[] = "bsmtp";
  static const unsigned char sender[] = "sender@example";
  static const unsigned char recipient_one[] = "one@example";
  static const unsigned char recipient_two[] = "two@example";
  static const unsigned char header_one[] =
    "Authentication-Results: old.one\n";
  static const unsigned char header_two[] =
    "Subject: folded\n continuation\n";
  static const unsigned char header_three[] =
    "Authentication-Results: old.two\n";
  static const unsigned char body[] =
    {'l','i','n','e','1','\n','c','r','l','f','\r','\n',
     'b','a','r','e','\r','\0','t','a','i','l','\n'};
  const unsigned char *cursor;
  const unsigned char *end;
  uint32_t payload_length;
  uint16_t length;
  size_t index;

  if (frame_length < HARNESS_FRAME_HEADER + 18U + HARNESS_BUILD_ID ||
      memcmp(frame, "DXI1", 4U) != 0 || frame[4] != 1U ||
      frame[5] != 1U || frame[6] != 0U || frame[7] != 0U)
    return 0;
  payload_length = harness_read_u32(frame + 8U);
  if (frame_length != HARNESS_FRAME_HEADER + payload_length)
    return 0;
  cursor = frame + HARNESS_FRAME_HEADER;
  end = frame + frame_length;
  if (harness_read_u16(cursor) != HARNESS_BUILD_ID ||
      cursor[2] != 1U || cursor[3] != 2U ||
      harness_read_u16(cursor + 4U) != 2U ||
      harness_read_u16(cursor + 6U) != 3U ||
      harness_read_u16(cursor + 8U) != sizeof(peer) - 1U ||
      harness_read_u16(cursor + 10U) != 2525U ||
      harness_read_u16(cursor + 12U) != sizeof(helo) - 1U ||
      harness_read_u16(cursor + 14U) != sizeof(protocol) - 1U ||
      harness_read_u16(cursor + 16U) != sizeof(sender) - 1U)
    return 0;
  cursor += 18U;
  for (index = 0; index < HARNESS_BUILD_ID; index++)
    if (!((cursor[index] >= '0' && cursor[index] <= '9') ||
          (cursor[index] >= 'a' && cursor[index] <= 'f')))
      return 0;
  if (memcmp(cursor, DKIM2_EXIM_BUILD_ID_V1, HARNESS_BUILD_ID) != 0)
    return 0;
  cursor += HARNESS_BUILD_ID;
  if (!harness_consume_slice(&cursor, end, peer, sizeof(peer) - 1U) ||
      !harness_consume_slice(&cursor, end, helo, sizeof(helo) - 1U) ||
      !harness_consume_slice(
        &cursor, end, protocol, sizeof(protocol) - 1U) ||
      !harness_consume_slice(&cursor, end, sender, sizeof(sender) - 1U))
    return 0;
#define HARNESS_CONSUME_LENGTHED(expected) \
  do { \
    if ((size_t)(end - cursor) < 2U) \
      return 0; \
    length = harness_read_u16(cursor); \
    cursor += 2U; \
    if (length != sizeof(expected) - 1U || \
        !harness_consume_slice( \
          &cursor, end, expected, sizeof(expected) - 1U)) \
      return 0; \
  } while (0)
  HARNESS_CONSUME_LENGTHED(recipient_one);
  HARNESS_CONSUME_LENGTHED(recipient_two);
#undef HARNESS_CONSUME_LENGTHED
#define HARNESS_CONSUME_HEADER(expected) \
  do { \
    if ((size_t)(end - cursor) < 4U || \
        harness_read_u32(cursor) != sizeof(expected) - 1U) \
      return 0; \
    cursor += 4U; \
    if (!harness_consume_slice( \
          &cursor, end, expected, sizeof(expected) - 1U)) \
      return 0; \
  } while (0)
  HARNESS_CONSUME_HEADER(header_one);
  HARNESS_CONSUME_HEADER(header_two);
  HARNESS_CONSUME_HEADER(header_three);
#undef HARNESS_CONSUME_HEADER
  if ((size_t)(end - cursor) < 4U ||
      harness_read_u32(cursor) != sizeof(body))
    return 0;
  cursor += 4U;
  return harness_consume_slice(&cursor, end, body, sizeof(body)) &&
    cursor == end;
}

/* harness_peer_main drives one request through an independent socket peer. */
static void *
harness_peer_main(void *opaque)
{
  struct harness_peer *peer = opaque;
  unsigned char header[HARNESS_FRAME_HEADER];
  unsigned char *request = NULL;
  uint32_t payload_length;
  size_t frame_length;
  int connection = accept(peer->listener, NULL, NULL);
  unsigned char trailing;
  ssize_t count;

  if (connection < 0 || !harness_read_all(connection, header, sizeof(header)))
    goto done;
  payload_length = harness_read_u32(header + 8U);
  if (payload_length > 34079124U)
    goto done;
  frame_length = HARNESS_FRAME_HEADER + payload_length;
  request = malloc(frame_length);
  if (!request)
    goto done;
  memcpy(request, header, sizeof(header));
  if (!harness_read_all(
        connection, request + HARNESS_FRAME_HEADER, payload_length))
    goto done;
  do
    count = read(connection, &trailing, 1U);
  while (count < 0 && errno == EINTR);
  if (count != 0)
    goto done;
  peer->request_valid = harness_validate_request(request, frame_length);
  if (!harness_write_all(
        connection, peer->response, peer->response_length))
    peer->request_valid = 0;

done:
  free(request);
  if (connection >= 0)
    close(connection);
  return NULL;
}

/* harness_response creates one independent bounded response frame. */
static size_t
harness_response(
  unsigned char *output,
  uint8_t decision,
  uint8_t reason,
  const uint16_t *removals,
  uint16_t removal_count,
  uint16_t add_name,
  const unsigned char *add_value,
  uint16_t add_length,
  const unsigned char *locator)
{
  unsigned char *cursor = output + HARNESS_FRAME_HEADER;
  uint16_t index;
  uint32_t payload_length =
    8U + 2U * removal_count + add_length + (locator ? 32U : 0U);

  memcpy(output, "DXI1", 4U);
  output[4] = 1U;
  output[5] = 2U;
  output[6] = 0U;
  output[7] = 0U;
  harness_write_u32(output + 8U, payload_length);
  cursor[0] = decision;
  cursor[1] = reason;
  harness_write_u16(cursor + 2U, removal_count);
  harness_write_u16(cursor + 4U, add_name);
  harness_write_u16(cursor + 6U, add_length);
  cursor += 8U;
  for (index = 0; index < removal_count; index++)
    {
    harness_write_u16(cursor, removals[index]);
    cursor += 2U;
    }
  if (add_length)
    memcpy(cursor, add_value, add_length);
  cursor += add_length;
  if (locator)
    memcpy(cursor, locator, 32U);
  return HARNESS_FRAME_HEADER + payload_length;
}

/* harness_set_string_option updates one documented local-scan option. */
static void
harness_set_string_option(const char *name, uschar *value)
{
  int index;

  for (index = 0; index < local_scan_options_count; index++)
    if (strcmp(local_scan_options[index].name, name) == 0)
      {
      *(uschar **)local_scan_options[index].v.value = value;
      return;
      }
  HARNESS_ASSERT(0);
}

/* harness_set_int_option updates one documented local-scan option. */
static void
harness_set_int_option(const char *name, int value)
{
  int index;

  for (index = 0; index < local_scan_options_count; index++)
    if (strcmp(local_scan_options[index].name, name) == 0)
      {
      *(int *)local_scan_options[index].v.value = value;
      return;
      }
  HARNESS_ASSERT(0);
}

/* harness_header_new allocates one Exim-compatible header fixture. */
static header_line *
harness_header_new(int type, const unsigned char *text, size_t length)
{
  header_line *header = calloc(1U, sizeof(*header));

  HARNESS_ASSERT(header != NULL);
  if (!header)
    return NULL;
  header->text = malloc(length + 1U);
  HARNESS_ASSERT(header->text != NULL);
  if (!header->text)
    {
    free(header);
    return NULL;
    }
  memcpy(header->text, text, length);
  header->text[length] = '\0';
  header->type = type;
  header->slen = (int)length;
  return header;
}

/* harness_headers_reset installs ordered, duplicate, folded, and deleted fields. */
static void
harness_headers_reset(void)
{
  static const unsigned char first[] = "Authentication-Results: old.one\n";
  static const unsigned char folded[] = "Subject: folded\n continuation\n";
  static const unsigned char deleted[] = "X-Deleted: absent\n";
  static const unsigned char second[] = "Authentication-Results: old.two\n";
  header_line *one = harness_header_new(' ', first, sizeof(first) - 1U);
  header_line *two = harness_header_new(' ', folded, sizeof(folded) - 1U);
  header_line *three = harness_header_new('*', deleted, sizeof(deleted) - 1U);
  header_line *four = harness_header_new(' ', second, sizeof(second) - 1U);

  one->next = two;
  two->next = three;
  three->next = four;
  header_list = one;
  header_last = four;
}

/* harness_headers_free releases every harness-owned header field. */
static void
harness_headers_free(void)
{
  header_line *header = header_list;

  while (header)
    {
    header_line *next = header->next;
    free(header->text);
    free(header);
    header = next;
    }
  header_list = NULL;
  header_last = NULL;
}

/* harness_socket creates a restrictive same-UID peer endpoint. */
static int
harness_socket(char *path, size_t path_length)
{
  struct sockaddr_un address;
  socklen_t address_length;
  int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  int bind_result;

  if (harness_socket_blocked)
    return -1;
  HARNESS_ASSERT(listener >= 0);
  if (listener < 0)
    return -1;
  snprintf(path, path_length, "/tmp/dkim2-exim-harness-%ld.sock", (long)getpid());
  unlink(path);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path, strlen(path) + 1U);
#if defined(__APPLE__) || defined(__FreeBSD__)
  address.sun_len = (unsigned char)(
    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1U);
#endif
  address_length = (socklen_t)(
    offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1U);
  bind_result = bind(listener, (struct sockaddr *)&address, address_length);
  if (bind_result != 0)
    {
    int bind_errno = errno;

    close(listener);
    unlink(path);
    if (bind_errno == EPERM || bind_errno == EACCES)
      {
      fprintf(stderr,
        "local_scan harness: AF_UNIX bind unavailable (%s); "
        "socket-dependent tests skipped\n", strerror(bind_errno));
      harness_socket_blocked = 1;
      return -1;
      }
    fprintf(stderr, "local_scan harness socket setup failed: %s\n",
      strerror(bind_errno));
    HARNESS_ASSERT(0);
    return -1;
    }
  HARNESS_ASSERT(chmod(path, 0600) == 0);
  HARNESS_ASSERT(listen(listener, 1) == 0);
  return listener;
}

/* harness_body_fd creates one exact Exim -D body fixture. */
static int
harness_body_fd(void)
{
  static const unsigned char body[] =
    {'l','i','n','e','1','\n','c','r','l','f','\r','\n',
     'b','a','r','e','\r','\0','t','a','i','l','\n'};
  unsigned char prefix[HARNESS_BODY_OFFSET];
  char path[] = "/tmp/dkim2-exim-body-XXXXXX";
  int fd = mkstemp(path);

  HARNESS_ASSERT(fd >= 0);
  unlink(path);
  memset(prefix, 'Q', sizeof(prefix));
  HARNESS_ASSERT(harness_write_all(fd, prefix, sizeof(prefix)));
  HARNESS_ASSERT(harness_write_all(fd, body, sizeof(body)));
  HARNESS_ASSERT(lseek(fd, 3, SEEK_SET) == 3);
  return fd;
}

/* harness_start_peer starts one independent response peer. */
static pthread_t
harness_start_peer(struct harness_peer *peer)
{
  pthread_t thread;
  int result = pthread_create(&thread, NULL, harness_peer_main, peer);

  HARNESS_ASSERT(result == 0);
  return thread;
}

/* harness_prepare_globals installs exact scalar and envelope fixtures. */
static void
harness_prepare_globals(char *socket_path)
{
  static recipient_item recipients[2];
  static uschar recipient_one[] = "one@example";
  static uschar recipient_two[] = "two@example";
  static uschar protocol[] = "bsmtp";
  static uschar peer[] = "192.0.2.10";
  static uschar sender[] = "sender@example";
  static uschar spool[] = "unix_lf";
  static uschar failure[] = "tempfail";

  memset(recipients, 0, sizeof(recipients));
  recipients[0].address = recipient_one;
  recipients[1].address = recipient_two;
  recipients_count = 2;
  recipients_list = recipients;
  received_protocol = protocol;
  sender_host_address = peer;
  sender_host_port = 2525;
  sender_address = sender;
  smtp_input = TRUE;
  smtp_batched_input = TRUE;
  harness_set_string_option("dkim2_failure_mode", failure);
  harness_set_int_option("dkim2_max_message_bytes", 33554432);
  harness_set_string_option("dkim2_socket", US socket_path);
  harness_set_string_option("dkim2_spool_format", spool);
  harness_set_int_option("dkim2_timeout", 1);
}

/* harness_test_accept proves exact request, prevalidation, mutation, and ownership. */
static void
harness_test_accept(void)
{
  static const unsigned char add_value[] = " mx.example; dkim2=pass";
  static const unsigned char locator[] = "ABCDEFGHIJKLMNOPQRSTUVWXabcdefgh";
  static const uint16_t removals[] = {2U, 1U};
  struct harness_peer peer;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  pthread_t thread;
  uschar *return_text = US"sentinel";
  int fd;
  int result;

  memset(&peer, 0, sizeof(peer));
  peer.listener = harness_socket(socket_path, sizeof(socket_path));
  if (peer.listener < 0)
    return;
  peer.response_length = harness_response(
    peer.response, 1U, 0U, removals, 2U, 1U,
    add_value, (uint16_t)(sizeof(add_value) - 1U), locator);
  harness_prepare_globals(socket_path);
  harness_headers_reset();
  fd = harness_body_fd();
  thread = harness_start_peer(&peer);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(pthread_join(thread, NULL) == 0);
  HARNESS_ASSERT(result == LOCAL_SCAN_ACCEPT);
  HARNESS_ASSERT(peer.request_valid);
  HARNESS_ASSERT(return_text != NULL);
  HARNESS_ASSERT(memcmp(return_text, locator, sizeof(locator) - 1U) == 0);
  HARNESS_ASSERT(return_text[sizeof(locator) - 1U] == '\0');
  HARNESS_ASSERT(header_list != NULL);
  HARNESS_ASSERT(
    memcmp(header_list->text, "Authentication-Results:", 23U) == 0);
  HARNESS_ASSERT(header_list->next->type == '*');
  HARNESS_ASSERT(header_list->next->next->next->next->type == '*');
  HARNESS_ASSERT(lseek(fd, 0, SEEK_CUR) == HARNESS_BODY_OFFSET);
  HARNESS_ASSERT(fcntl(fd, F_GETFD) >= 0);
  close(fd);
  close(peer.listener);
  unlink(socket_path);
  free(return_text);
  harness_headers_free();
}

/* harness_test_malformed_response proves actions are atomic before mutation. */
static void
harness_test_malformed_response(void)
{
  static const uint16_t ascending[] = {1U, 2U};
  struct harness_peer peer;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  pthread_t thread;
  uschar *return_text = NULL;
  header_line *original_first;
  header_line *original_last;
  int fd;
  int result;

  memset(&peer, 0, sizeof(peer));
  peer.listener = harness_socket(socket_path, sizeof(socket_path));
  if (peer.listener < 0)
    return;
  peer.response_length = harness_response(
    peer.response, 1U, 0U, ascending, 2U, 0U, NULL, 0U, NULL);
  harness_prepare_globals(socket_path);
  harness_headers_reset();
  original_first = header_list;
  original_last = header_last;
  fd = harness_body_fd();
  thread = harness_start_peer(&peer);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(pthread_join(thread, NULL) == 0);
  HARNESS_ASSERT(result == LOCAL_SCAN_TEMPREJECT_NOLOGHDR);
  HARNESS_ASSERT(peer.request_valid);
  HARNESS_ASSERT(header_list == original_first);
  HARNESS_ASSERT(header_last == original_last);
  HARNESS_ASSERT(header_list->type != '*');
  HARNESS_ASSERT(header_last->type != '*');
  HARNESS_ASSERT(return_text != NULL);
  HARNESS_ASSERT(strcmp(
    CCS return_text, "DKIM2 service temporarily unavailable") == 0);
  HARNESS_ASSERT(lseek(fd, 0, SEEK_CUR) == HARNESS_BODY_OFFSET);
  close(fd);
  close(peer.listener);
  unlink(socket_path);
  free(return_text);
  harness_headers_free();
}

/* harness_test_reject proves the exact fixed NOLOGHDR permanent mapping. */
static void
harness_test_reject(void)
{
  struct harness_peer peer;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  pthread_t thread;
  uschar *return_text = NULL;
  int fd;
  int result;

  memset(&peer, 0, sizeof(peer));
  peer.listener = harness_socket(socket_path, sizeof(socket_path));
  if (peer.listener < 0)
    return;
  peer.response_length = harness_response(
    peer.response, 2U, 1U, NULL, 0U, 0U, NULL, 0U, NULL);
  harness_prepare_globals(socket_path);
  harness_headers_reset();
  fd = harness_body_fd();
  thread = harness_start_peer(&peer);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(pthread_join(thread, NULL) == 0);
  HARNESS_ASSERT(result == LOCAL_SCAN_REJECT_NOLOGHDR);
  HARNESS_ASSERT(strcmp(
    CCS return_text, "DKIM2 policy rejected the message") == 0);
  HARNESS_ASSERT(header_list->type != '*' && header_last->type != '*');
  close(fd);
  close(peer.listener);
  unlink(socket_path);
  free(return_text);
  harness_headers_free();
}

/* harness_test_accept_without_locator proves NULL local_scan_data ownership. */
static void
harness_test_accept_without_locator(void)
{
  struct harness_peer peer;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  pthread_t thread;
  uschar *return_text = US"sentinel";
  int fd;
  int result;

  memset(&peer, 0, sizeof(peer));
  peer.listener = harness_socket(socket_path, sizeof(socket_path));
  if (peer.listener < 0)
    return;
  peer.response_length = harness_response(
    peer.response, 1U, 0U, NULL, 0U, 0U, NULL, 0U, NULL);
  harness_prepare_globals(socket_path);
  harness_headers_reset();
  fd = harness_body_fd();
  thread = harness_start_peer(&peer);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(pthread_join(thread, NULL) == 0);
  HARNESS_ASSERT(result == LOCAL_SCAN_ACCEPT);
  HARNESS_ASSERT(peer.request_valid);
  HARNESS_ASSERT(return_text == NULL);
  HARNESS_ASSERT(header_list->type != '*' && header_last->type != '*');
  close(fd);
  close(peer.listener);
  unlink(socket_path);
  harness_headers_free();
}

/* harness_test_tempfail proves the exact fixed NOLOGHDR temporary mapping. */
static void
harness_test_tempfail(void)
{
  struct harness_peer peer;
  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  pthread_t thread;
  uschar *return_text = NULL;
  int fd;
  int result;

  memset(&peer, 0, sizeof(peer));
  peer.listener = harness_socket(socket_path, sizeof(socket_path));
  if (peer.listener < 0)
    return;
  peer.response_length = harness_response(
    peer.response, 3U, 2U, NULL, 0U, 0U, NULL, 0U, NULL);
  harness_prepare_globals(socket_path);
  harness_headers_reset();
  fd = harness_body_fd();
  thread = harness_start_peer(&peer);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(pthread_join(thread, NULL) == 0);
  HARNESS_ASSERT(result == LOCAL_SCAN_TEMPREJECT_NOLOGHDR);
  HARNESS_ASSERT(peer.request_valid);
  HARNESS_ASSERT(strcmp(
    CCS return_text, "DKIM2 service temporarily unavailable") == 0);
  HARNESS_ASSERT(header_list->type != '*' && header_last->type != '*');
  close(fd);
  close(peer.listener);
  unlink(socket_path);
  free(return_text);
  harness_headers_free();
}

/* harness_test_pre_body_config_failure proves the spool declaration gate is early. */
static void
harness_test_pre_body_config_failure(void)
{
  static uschar invalid_spool[] = "wire";
  uschar *return_text = NULL;
  int fd;
  int result;

  harness_prepare_globals("/tmp/unreached.sock");
  harness_set_string_option("dkim2_spool_format", invalid_spool);
  harness_headers_reset();
  fd = harness_body_fd();
  HARNESS_ASSERT(lseek(fd, 7, SEEK_SET) == 7);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(result == LOCAL_SCAN_TEMPREJECT_NOLOGHDR);
  HARNESS_ASSERT(lseek(fd, 0, SEEK_CUR) == 7);
  HARNESS_ASSERT(fcntl(fd, F_GETFD) >= 0);
  close(fd);
  free(return_text);
  harness_headers_free();
}

/* harness_test_fail_open_declaration_rejected proves C never owns mail acceptance. */
static void
harness_test_fail_open_declaration_rejected(void)
{
  static uschar fail_open[] = "fail_open";
  uschar *return_text = NULL;
  int fd;
  int result;

  harness_prepare_globals("/tmp/unreached.sock");
  harness_set_string_option("dkim2_failure_mode", fail_open);
  harness_headers_reset();
  fd = harness_body_fd();
  HARNESS_ASSERT(lseek(fd, 7, SEEK_SET) == 7);
  result = local_scan(fd, &return_text);
  HARNESS_ASSERT(result == LOCAL_SCAN_TEMPREJECT_NOLOGHDR);
  HARNESS_ASSERT(lseek(fd, 0, SEEK_CUR) == 7);
  HARNESS_ASSERT(fcntl(fd, F_GETFD) >= 0);
  close(fd);
  free(return_text);
  harness_headers_free();
}

/* harness_test_frame_caps freezes the independent exact and max-plus-one oracles. */
static void
harness_test_frame_caps(void)
{
  size_t request_payload =
    18U + 671U + 516000U + 8000U + 4U + 33554431U;
  size_t response_payload = 8U + 4000U + 65535U + 32U;

  HARNESS_ASSERT(request_payload == 34079124U);
  HARNESS_ASSERT(request_payload + HARNESS_FRAME_HEADER == 34079136U);
  HARNESS_ASSERT(request_payload + 1U == 34079125U);
  HARNESS_ASSERT(response_payload == 69575U);
  HARNESS_ASSERT(response_payload + HARNESS_FRAME_HEADER == 69587U);
  HARNESS_ASSERT(response_payload + 1U == 69576U);
}

/* expand_string supplies one bounded public expansion without diagnostics. */
#ifdef DKIM2_EXIM_EXPAND_STRING_2
const uschar *
expand_string_2(const uschar *input, BOOL *resetok)
{
  (void)resetok;
  if (input && strcmp(CCS input, "$sender_helo_name") == 0)
    return harness_helo;
  return NULL;
}
#else
uschar *
expand_string(uschar *input)
{
  if (input && strcmp(CCS input, "$sender_helo_name") == 0)
    return harness_helo;
  return NULL;
}
#endif

/* header_testname implements Exim's documented whitespace-before-colon match. */
BOOL
header_testname(
  const header_line *header,
  const uschar *name,
  int length,
  BOOL not_deleted)
{
  int offset = length;

  if (!header || !header->text || length < 1 ||
      (not_deleted && header->type == '*') ||
      header->slen <= length ||
      strncasecmp(CCS header->text, CCS name, (size_t)length) != 0)
    return FALSE;
  while (offset < header->slen &&
         (header->text[offset] == ' ' || header->text[offset] == '\t'))
    offset++;
  return offset < header->slen && header->text[offset] == ':';
}

/* header_remove marks one non-deleted matching occurrence as removed. */
void
header_remove(int occurrence, const uschar *name)
{
  header_line *header;
  int current = 0;
  int length = (int)strlen(CCS name);

  for (header = header_list; header; header = header->next)
    if (header_testname(header, name, length, TRUE) &&
        (occurrence <= 0 || ++current == occurrence))
      {
      header->type = '*';
      if (occurrence > 0)
        return;
      }
}

/* header_add_at_position prepends the one constant-formatted harness field. */
void
header_add_at_position(
  BOOL after,
  uschar *name,
  BOOL topnot,
  int type,
  const char *format,
  ...)
{
  char rendered[70000];
  va_list arguments;
  int length;
  header_line *header;

  HARNESS_ASSERT(after == FALSE && name == NULL && topnot == TRUE);
  HARNESS_ASSERT(strcmp(format, "Authentication-Results: %s\n") == 0);
  va_start(arguments, format);
  length = vsnprintf(rendered, sizeof(rendered), format, arguments);
  va_end(arguments);
  HARNESS_ASSERT(length > 0 && (size_t)length < sizeof(rendered));
  header = harness_header_new(type, (unsigned char *)rendered, (size_t)length);
  header->next = header_list;
  header_list = header;
  if (!header_last)
    header_last = header;
}

/* log_write accepts only the production's closed reason-class format. */
void
log_write(unsigned int selector, int flags, const char *format, ...)
{
  HARNESS_ASSERT(selector == 0);
  HARNESS_ASSERT(flags == LOG_MAIN);
  HARNESS_ASSERT(strcmp(
    format, "dkim2 local_scan failure class=%s") == 0);
  harness_log_count++;
}

/* store_get_perm_3 models Exim permanent storage ownership. */
void *
store_get_perm_3(
  int size,
  const void *prototype,
  const char *function,
  int line)
{
  (void)prototype;
  (void)function;
  (void)line;
  return size > 0 ? malloc((size_t)size) : NULL;
}

/* main runs the actual production local_scan function through independent peers. */
int
main(void)
{
  harness_test_frame_caps();
  harness_test_accept();
  harness_test_accept_without_locator();
  harness_test_malformed_response();
  harness_test_reject();
  harness_test_tempfail();
  harness_test_pre_body_config_failure();
  harness_test_fail_open_declaration_rejected();
  HARNESS_ASSERT(harness_log_count >= (harness_socket_blocked ? 1 : 2));
  if (harness_failures)
    return 1;
  return 0;
}
