/*
 * Independent compile probe for the exact public local_scan API.
 *
 * The emitted contract is deterministic and deliberately excludes paths,
 * timestamps, compiler identities, environment values, and the derived build
 * identifier.
 */

#define LOCAL_SCAN
#include "local_scan.h"

#include <stddef.h>
#include <stdio.h>

#ifndef DKIM2_EXIM_VERSION
#error "DKIM2_EXIM_VERSION must name the exact source version"
#endif

#ifndef DKIM2_EXIM_SOURCE_SHA256
#error "DKIM2_EXIM_SOURCE_SHA256 must name the verified source input"
#endif

#ifndef DKIM2_EXIM_HEADER_SHA256
#error "DKIM2_EXIM_HEADER_SHA256 must name the frozen local_scan.h fixture"
#endif

#ifndef DKIM2_EXIM_TRANSPORT_FILTER_PATCH_SHA256
#error "DKIM2_EXIM_TRANSPORT_FILTER_PATCH_SHA256 must name the applied source patch"
#endif

#ifndef DKIM2_EXIM_I18N
#error "DKIM2_EXIM_I18N must record the probed international-mail feature"
#endif

static int (*const probe_local_scan)(int, uschar **) = local_scan;
#ifdef DKIM2_EXIM_EXPAND_STRING_2
static const uschar *(*const probe_expand_string)(const uschar *, BOOL *) =
  expand_string_2;
#else
static uschar *(*const probe_expand_string)(uschar *) = expand_string;
#endif
static void (*const probe_header_add_at_position)(
  BOOL, uschar *, BOOL, int, const char *, ...) = header_add_at_position;
static void (*const probe_header_remove)(int, const uschar *) = header_remove;
static BOOL (*const probe_header_testname)(
  const header_line *, const uschar *, int, BOOL) = header_testname;
static void (*const probe_log_write)(
  unsigned int, int, const char *, ...) = log_write;
static void *(*const probe_store_get_3)(
  int, const void *, const char *, int) = store_get_3;
static void *(*const probe_store_get_perm_3)(
  int, const void *, const char *, int) = store_get_perm_3;

_Static_assert(sizeof(((header_line *)0)->type) == sizeof(int),
  "header_line.type changed");
_Static_assert(sizeof(((header_line *)0)->slen) == sizeof(int),
  "header_line.slen changed");
_Static_assert(sizeof(((recipient_item *)0)->pno) == sizeof(int),
  "recipient_item.pno changed");
_Static_assert(sizeof(((recipient_item *)0)->dsn_flags) == sizeof(int),
  "recipient_item.dsn_flags changed");
_Static_assert(offsetof(header_line, next) == 0U,
  "header_line.next changed");
_Static_assert(offsetof(recipient_item, address) == 0U,
  "recipient_item.address changed");
_Static_assert(SPOOL_DATA_START_OFFSET > 0,
  "SPOOL_DATA_START_OFFSET changed");
_Static_assert(_Generic(&header_list, header_line **: 1, default: 0),
  "header_list type changed");
_Static_assert(_Generic(&recipients_count, int *: 1, default: 0),
  "recipients_count type changed");
_Static_assert(_Generic(&recipients_list, recipient_item **: 1, default: 0),
  "recipients_list type changed");
_Static_assert(_Generic(
    &sender_address, const unsigned char **: 1, default: 0),
  "sender_address type changed");
_Static_assert(_Generic(&sender_host_address, uschar **: 1, default: 0),
  "sender_host_address type changed");
_Static_assert(_Generic(&sender_host_port, int *: 1, default: 0),
  "sender_host_port type changed");
_Static_assert(_Generic(&smtp_batched_input, BOOL *: 1, default: 0),
  "smtp_batched_input type changed");
_Static_assert(_Generic(&smtp_input, BOOL *: 1, default: 0),
  "smtp_input type changed");

/* local_scan is a link-only probe definition with the declared ABI. */
int
local_scan(int fd, uschar **return_text)
{
  (void)fd;
  (void)return_text;
  return LOCAL_SCAN_ACCEPT;
}

/* expand_string is a link-only probe definition with the declared ABI. */
#ifdef DKIM2_EXIM_EXPAND_STRING_2
const uschar *
expand_string_2(const uschar *value, BOOL *resetok)
{
  (void)resetok;
  return value;
}
#else
uschar *
expand_string(uschar *value)
{
  return value;
}
#endif

/* header_add_at_position is a link-only probe definition with the declared ABI. */
void
header_add_at_position(
  BOOL after,
  uschar *name,
  BOOL topnot,
  int type,
  const char *format,
  ...)
{
  (void)after;
  (void)name;
  (void)topnot;
  (void)type;
  (void)format;
}

/* header_remove is a link-only probe definition with the declared ABI. */
void
header_remove(int occurrence, const uschar *name)
{
  (void)occurrence;
  (void)name;
}

/* header_testname is a link-only probe definition with the declared ABI. */
BOOL
header_testname(
  const header_line *header,
  const uschar *name,
  int length,
  BOOL not_deleted)
{
  (void)header;
  (void)name;
  (void)length;
  (void)not_deleted;
  return FALSE;
}

/* log_write is a link-only probe definition with the declared ABI. */
void
log_write(unsigned int selector, int flags, const char *format, ...)
{
  (void)selector;
  (void)flags;
  (void)format;
}

/* store_get_3 is a link-only probe definition with the declared ABI. */
void *
store_get_3(int size, const void *prototype, const char *function, int line)
{
  (void)size;
  (void)prototype;
  (void)function;
  (void)line;
  return NULL;
}

/* store_get_perm_3 is a link-only probe definition with the declared ABI. */
void *
store_get_perm_3(
  int size,
  const void *prototype,
  const char *function,
  int line)
{
  (void)size;
  (void)prototype;
  (void)function;
  (void)line;
  return NULL;
}

/* main emits the build-ID-free ABI contract after all type checks compile. */
int
main(void)
{
  (void)probe_local_scan;
  (void)probe_expand_string;
  (void)probe_header_add_at_position;
  (void)probe_header_remove;
  (void)probe_header_testname;
  (void)probe_log_write;
  (void)probe_store_get_3;
  (void)probe_store_get_perm_3;
  printf("format=dkim2-exim-probe-contract-v1\n");
  printf("exim_version=%s\n", DKIM2_EXIM_VERSION);
  printf("source_sha256=%s\n", DKIM2_EXIM_SOURCE_SHA256);
  printf("local_scan_header_sha256=%s\n", DKIM2_EXIM_HEADER_SHA256);
  printf("transport_filter_patch_sha256=%s\n",
    DKIM2_EXIM_TRANSPORT_FILTER_PATCH_SHA256);
  printf("feature_international_mail=%d\n", DKIM2_EXIM_I18N);
  printf("local_scan_abi_major=%d\n", LOCAL_SCAN_ABI_VERSION_MAJOR);
  printf("local_scan_abi_minor=%d\n", LOCAL_SCAN_ABI_VERSION_MINOR);
  printf("spool_data_start_offset=%d\n", SPOOL_DATA_START_OFFSET);
  printf("local_scan_accept=%d\n", LOCAL_SCAN_ACCEPT);
  printf("local_scan_reject_nologhdr=%d\n", LOCAL_SCAN_REJECT_NOLOGHDR);
  printf("local_scan_tempreject_nologhdr=%d\n",
    LOCAL_SCAN_TEMPREJECT_NOLOGHDR);
  printf("header_line_fields=next:pointer,type:int,slen:int,text:uschar_pointer\n");
  printf("recipient_item_fields=address:const_uschar_pointer,pno:int,"
    "errors_to:const_uschar_pointer,orcpt:uschar_pointer,dsn_flags:int\n");
  printf("prototype_local_scan=int(int,uschar_double_pointer)\n");
#ifdef DKIM2_EXIM_EXPAND_STRING_2
  printf("prototype_expand_string_2=const_uschar_pointer(const_uschar_pointer,BOOL_pointer)\n");
#else
  printf("prototype_expand_string=uschar_pointer(uschar_pointer)\n");
#endif
  printf("prototype_header_add_at_position="
    "void(BOOL,uschar_pointer,BOOL,int,const_char_pointer,varargs)\n");
  printf("prototype_header_remove=void(int,const_uschar_pointer)\n");
  printf("prototype_header_testname="
    "BOOL(const_header_line_pointer,const_uschar_pointer,int,BOOL)\n");
  printf("prototype_log_write="
    "void(unsigned_int,int,const_char_pointer,varargs)\n");
  printf("prototype_store_get_3="
    "void_pointer(int,const_void_pointer,const_char_pointer,int)\n");
  printf("prototype_store_get_perm_3="
    "void_pointer(int,const_void_pointer,const_char_pointer,int)\n");
  return 0;
}
