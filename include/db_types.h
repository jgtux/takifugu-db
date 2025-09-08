#ifndef DB_TYPES_H
#define DB_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#define FUGUID_LEN 12
#define FUGUID_VERSION 0xF1

/* Error codes */
typedef enum {
  DB_SUCCESS = 0,
  DB_ERROR_NULL_PARAM = -1,
  DB_ERROR_OUT_OF_MEMORY = -2,
  DB_ERROR_TABLE_NOT_FOUND = -3,
  DB_ERROR_COLUMN_MISMATCH = -4,
  DB_ERROR_DUPLICATE_NAME = -5,
  DB_ERROR_INVALID_INDEX = -6,
  DB_ERROR_IN_USAGE = -7,
  DB_ERROR_NOT_FOUND = -8
} int_return_type;

/* Column types */
typedef enum {
  COL_INT,
  COL_INT64,
  COL_UINT,
  COL_UINT64,
  COL_FLOAT64,
  COL_DYNAMIC_STR,
  COL_STRICT_STR,
  COL_BOOL,
  COL_BYTE,
  COL_FUGU_ID
} col_type;

/* Forward declarations */
typedef struct column column_t;
typedef struct column_value column_val_t;
typedef struct row row_t;
typedef struct table table_t;
typedef struct database db_t;
typedef struct fugu_id fugu_id_t;

/* Core structures */
struct column {
  char *name;
  col_type type;
  size_t len;
  bool nullable;
};

struct column_value {
  void *ptr;
  size_t size;
};

struct row {
  column_val_t *values;
  size_t len;
};

struct table {
  char *name;
  column_t *columns;
  size_t cols_len;
  row_t *rows;
  size_t rows_len;
  size_t row_cap;
  atomic_int ref_count;
  atomic_bool marked_for_del;
  pthread_mutex_t tbl_mutex;
  size_t table_index;
};

struct database {
  char *name;
  table_t *tables;
  size_t tbls_len;
  size_t table_cap;
  pthread_mutex_t db_mutex;
};

struct fugu_id {
  unsigned char data[FUGUID_LEN];
};

/* Utility functions */
size_t typeSize(col_type type, size_t len);

#endif /* DB_TYPES_H */
