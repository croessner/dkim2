#ifndef STORE_H
#define STORE_H

enum {
  POOL_MAIN,
  POOL_PERM,
  POOL_CONFIG,
  POOL_SEARCH,
  POOL_MESSAGE,
  POOL_TAINT_BASE,
  POOL_TAINT_MAIN = POOL_TAINT_BASE,
  POOL_TAINT_PERM,
  POOL_TAINT_CONFIG,
  POOL_TAINT_SEARCH,
  POOL_TAINT_MESSAGE,
  N_PAIRED_POOLS
};

extern void *store_last_get[];
extern int store_pool;

#define GET_UNTAINTED (const void *)0
#define GET_TAINTED (const void *)1

#endif
