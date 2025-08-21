#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#define COMPUUID_LEN 16
#define COMPUUID_VERSION 0x01

/* ----------------------------------------------------------------------------- */

// data structs

typedef enum {
  COL_INT,
  COL_INT64,
  COL_UINT,
  COL_UINT64,
  COL_FLOAT64,
  COL_STR,
  COL_STRICT_STR,
  COL_BOOL,
  COL_BYTE,
  COL_CO_UUID
} col_type;

typedef struct column {
  char *name;
  col_type type;
  size_t len;
  bool nullable;
} column_t;

typedef struct column_value {
  void *ptr;
  size_t size;
} column_val_t;

typedef struct row {
  column_val_t *values;
  size_t len;
} row_t;

typedef struct table {
  column_t *columns;
  size_t cols_len;
  row_t *rows;
  size_t rows_len;
  size_t row_cap;
} table_t;

typedef struct database {
  char *name;
  table_t *tables;
  size_t tbls_len;
  size_t table_cap;
} db_t;

typedef struct comp_uuid {
  unsigned char *raw;
} comp_uuid_t;

/* ----------------------------------------------------------------------------- */

// type size
static inline size_t type_size(col_type type, size_t len) {
  switch(type) {
  case COL_INT: return sizeof(int);
  case COL_INT64: return sizeof(int64_t);
  case COL_UINT: return sizeof(uint32_t);
  case COL_UINT64: return sizeof(uint64_t);
  case COL_FLOAT64: return sizeof(double);
  case COL_STRICT_STR: return len;
  case COL_BOOL: return sizeof(bool);
  case COL_BYTE: return sizeof(unsigned char);
  case COL_CO_UUID: return sizeof(comp_uuid_t);
  case COL_STR: return 0;
  default: return 0;
  }
}

/* ----------------------------------------------------------------------------- */

static void freeCell(col_type type, column_val_t *cell) {
  if (!cell || !cell->ptr) return;

  if (type == COL_CO_UUID) {
    comp_uuid_t *c = (comp_uuid_t*)cell->ptr;
    if (c) {
      if (c->raw) free(c->raw);
      free(c);
    }
  } else {
    free(cell->ptr); 
  }

  cell->ptr = NULL;
  cell->size = 0;
}

static void freeRow(table_t *tb, row_t *row) {}

/* ----------------------------------------------------------------------------- */

// create database 
static db_t *createDatabase(const char *name, size_t init_table_cap) {
  db_t *db = malloc(sizeof(db_t));
  if (!db) return NULL;
  db->name = strdup(name);
  db->tbls_len = 0;
  db->table_cap = init_table_cap;
  db->tables = malloc(init_table_cap * sizeof(table_t*));
  if (!db->tables) {
    free(db->name);
    free(db);
    return NULL;
  }
  return db;
}

/* ----------------------------------------------------------------------------- */

// create table 
static table_t *createTable(column_t *columns, size_t col_len, size_t init_row_cap) {
  if (!columns || col_len == 0) return NULL;

  table_t *tb = malloc(sizeof(table_t));
  if (!tb) return NULL;

  tb->columns = malloc(col_len * sizeof(column_t));
  if (!tb->columns) { free(tb); return NULL; }
  memcpy(tb->columns, columns, col_len * sizeof(column_t));
  tb->cols_len = col_len;

  tb->rows = malloc(init_row_cap * sizeof(row_t));
  if (!tb->rows) { free(tb->columns); free(tb); return NULL; }
  tb->rows_len = 0;
  tb->row_cap = init_row_cap;

  return tb;
}

/* ----------------------------------------------------------------------------- */

//create empty row
static row_t createEmptyRow(table_t *tb) {
  row_t row;

  row.len = tb->cols_len;
  row.values = malloc(sizeof(column_val_t) * tb->cols_len);

  for (size_t i = 0; i < tb->cols_len; i++) {
    size_t sz = type_size(tb->columns[i].type, tb->columns[i].len);
    row.values[i].size = sz;
    if (sz > 0) row.values[i].ptr = malloc(sz);
    else row.values[i].ptr = NULL;
  }

  return row;
}

// insert row
static int insertRow(table_t *tb, row_t row) {
  if (row.len != tb->cols_len) return -1;

  for (size_t i = 0; i < tb->cols_len; i++) {
    column_t *col = &tb->columns[i];
    column_val_t *val = &row.values[i];
    size_t expected = type_size(col->type, col->len);
    if (expected > 0 && val->size != expected) return -2;
    if ((col->type == COL_STR || col->type == COL_STRICT_STR) &&
        !col->nullable && val->ptr == NULL) return -3;
  }

  if (tb->rows_len >= tb->row_cap) {
    size_t new_cap = tb->row_cap ? tb->row_cap * 2 : 4;
    row_t *new_rows = realloc(tb->rows, new_cap * sizeof(row_t));
    if (!new_rows) return -4;
    tb->rows = new_rows;
    tb->row_cap = new_cap;
  }

  tb->rows[tb->rows_len++] = row;
  return 0;
}

// delete row
static int deleteRow(table_t *t, row_t row) {

}

/* ----------------------------------------------------------------------------- */

// set int val
static inline void setInt(row_t *row, size_t idx, int val) {
  *((int*)row->values[idx].ptr) = val;
}

// set int64 val
static inline void setInt64(row_t *row, size_t idx, int64_t val) {
  *((int64_t*)row->values[idx].ptr) = val;
}

// set uint val
static inline void setUint(row_t *row, size_t idx, uint32_t val) {
  *((uint32_t*)row->values[idx].ptr) = val;
}

// set uint64 val
static inline void setUint64(row_t *row, size_t idx, uint64_t val) {
  *((uint64_t*)row->values[idx].ptr) = val;  
}

// set bool val
static inline void setBool(row_t *row, size_t idx, bool val) {
  *((bool*)row->values[idx].ptr) = val;
}

// set double val
static inline void setDouble(row_t *row, size_t idx, double val) {
  *((double*)row->values[idx].ptr) = val;
}

// set string val
static void setStr(row_t *row, size_t idx, const char *str) {
  size_t len = strlen(str) + 1;

  if (row->values[idx].ptr) {
    free(row->values[idx].ptr);
  }

  row->values[idx].ptr = malloc(len);

  memcpy(row->values[idx].ptr, str, len);

  row->values[idx].size = len;
}

// set compact-uuid val
static void setCompactUUID(row_t *row, size_t idx, comp_uuid_t *val) {
  if (!row->values[idx].ptr) {
    row->values[idx].ptr = malloc(sizeof(comp_uuid_t));
  }

  comp_uuid_t *dest = (comp_uuid_t *)row->values[idx].ptr;

  if (dest->raw) {
    free(dest->raw);
  }
  
  dest->raw = malloc(COMPUUID_LEN);
  memcpy(dest->raw, val->raw, COMPUUID_LEN);
}

/* ----------------------------------------------------------------------------- */

// comp UUID generator
static comp_uuid_t *generateCompUUID(void) {
  comp_uuid_t *c_uuid = malloc(sizeof(comp_uuid_t));
  if (!c_uuid) return NULL;

  c_uuid->raw = malloc(COMPUUID_LEN);
  if (!c_uuid->raw) {
    free(c_uuid);
    return NULL;
  }

  // timestamp
  uint32_t ts = (uint32_t)time(NULL);
  uint32_t be_ts = htonl(ts);
  memcpy(c_uuid->raw, &be_ts, 4); 
  // version
  c_uuid->raw[4] = COMPUUID_VERSION;

  // 11 random node bytes
  for (int i = 0; i < 11; i++) {
    c_uuid->raw[5 + i] = (unsigned char)(rand() & 0xFF);
  }

  return c_uuid;
}

/* ----------------------------------------------------------------------------- */

// main
int main() {
  column_t cols[2];
  cols[0].name = "id"; cols[0].type = COL_INT; cols[0].nullable = false; cols[0].len = 0;
  cols[1].name = "name"; cols[1].type = COL_STR; cols[1].nullable = false; cols[1].len = 0;

  table_t *tb = createTable(cols, 2, 4);
  row_t r = createEmptyRow(tb);
  setInt(&r, 0, 42);
  setStr(&r, 1, "Alice");

  insertRow(tb, r);

  printf("Row inserted: id=%d, name=%s\n",
         *((int*)tb->rows[0].values[0].ptr),
         (char*)tb->rows[0].values[1].ptr);

  return 0;
}
