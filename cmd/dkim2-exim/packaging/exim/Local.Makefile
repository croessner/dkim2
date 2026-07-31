# Source-matched Exim Local/Makefile fragment for the DKIM2 local_scan module.
# Copy dkim2_local_scan.c and build-id-v1.h into Local/ before building.
HAVE_LOCAL_SCAN=yes
LOCAL_SCAN_SOURCE=Local/dkim2_local_scan.c
LOCAL_SCAN_HAS_OPTIONS=yes
CFLAGS += -DDKIM2_EXIM_SOURCE_MATCHED=1
