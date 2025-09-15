#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include "db_types.h"

/* Initialize global memory pools */
int initMemoryPools(void);

/* Cleanup global memory pools */
void destroyMemoryPools(void);

/* Pool-based allocation functions */
void *pooledMalloc(size_t size);
void pooledFree(void *ptr);
char *pooledStrdup(const char *str);

/* Statistics */
void printPoolStats(void);

#endif
