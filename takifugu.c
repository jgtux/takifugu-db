#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

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
  char *name;
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

// free cascade

static void freeCell(col_type type, column_val_t *cell) {
  if (!cell) {
    return;
  } else if (!cell->ptr) {
    cell->size = 0;
    return;
  }

  if (type == COL_CO_UUID) {
    comp_uuid_t *c = cell->ptr;
    if (c) {
      if (c->raw) {
        free(c->raw);
      }
      free(c);
    }
  } else {
    free(cell->ptr); 
  }

  cell->ptr = NULL;
  cell->size = 0;
}

static void freeRowContents(table_t *tb, row_t *row) {
  if (!row || !row->values) {
    return;
  } 

  for(size_t i = 0; i < row->len; i++) {
    freeCell(tb->columns[i].type, &row->values[i]);
  }

  free(row->values);
  row->values = NULL;
  row->len = 0;
}

static void freeTableContents(table_t *tb) {
  if (!tb)
    return;

  if (tb->rows && tb->rows_len > 0) {
    for (size_t i = 0; i < tb->rows_len; i++) {
      freeRowContents(tb, &tb->rows[i]);
    }
  }

  if (tb->columns) {
    for (size_t i = 0; i < tb->cols_len; i++) {
      if (tb->columns[i].name) {
        free(tb->columns[i].name); 
      }
    }
    free(tb->columns);
  }

  if (tb->rows) {
    free(tb->rows);
  }

  if (tb->name) {
    free(tb->name); 
  }

  tb->name = NULL;
  tb->columns = NULL;
  tb->rows = NULL;
  tb->cols_len = 0;
  tb->rows_len = 0;
  tb->row_cap = 0;
}

static void freeDatabase(db_t *db) {
  if (!db) {
    return;
  }
  
  if (db->tables && db->tbls_len > 0) {
    for (size_t i = 0; i < db->tbls_len; i++) {
      freeTableContents(&db->tables[i]);
    }
  }

  if (db->tables) {
    free(db->tables);
  }

  if (db->name) {
    free(db->name);
  }

  free(db);
}

/* ----------------------------------------------------------------------------- */

// create database 
static db_t *createDatabase(const char *name, size_t init_table_cap) {
  if (!name) return NULL;
  
  db_t *db = malloc(sizeof(db_t));
  if (!db) return NULL;
  
  db->name = strdup(name);
  if (!db->name) {
    free(db);
    return NULL;
  }
  
  db->tbls_len = 0;
  db->table_cap = init_table_cap ? init_table_cap : 1;
  db->tables = malloc(db->table_cap * sizeof(table_t));
  if (!db->tables) {
    free(db->name);
    free(db);
    return NULL;
  }
  return db;
}

static int deleteDatabase(db_t *db) {
  if (!db) return -1;
  freeDatabase(db);
  return 0;
}

/* ----------------------------------------------------------------------------- */

// create table

static int createTable(db_t *db, const char *name, column_t *columns,
                       size_t col_len, size_t init_row_cap) {
  if (!db || !columns || col_len == 0 || !name)
    return -1;
    
  if (db->tbls_len >= db->table_cap) {
    size_t new_cap = db->table_cap * 2;
    table_t *new_tables = realloc(db->tables, new_cap * sizeof(table_t));
    if (!new_tables)
      return -2;
    db->tables = new_tables;
    db->table_cap = new_cap;
  }
  
  table_t *tb = &db->tables[db->tbls_len];
  memset(tb, 0, sizeof(table_t));
  
  tb->name = strdup(name);
  if (!tb->name)
    return -3;
    
  tb->columns = malloc(col_len * sizeof(column_t));
  if (!tb->columns) {
    free(tb->name);
    return -4;
  }
  
  for (size_t i = 0; i < col_len; i++) {
    tb->columns[i].type = columns[i].type;
    tb->columns[i].len = columns[i].len;
    tb->columns[i].nullable = columns[i].nullable;
    
    if (columns[i].name) {
      tb->columns[i].name = strdup(columns[i].name);
      if (!tb->columns[i].name) {
        for (size_t j = 0; j < i; j++) {
          free(tb->columns[j].name);
        }
        free(tb->columns);
        free(tb->name);
        return -6;
      }
    } else {
      tb->columns[i].name = NULL;
    }
  }
  
  tb->cols_len = col_len;
  init_row_cap = init_row_cap ? init_row_cap : 4;
  tb->rows = malloc(init_row_cap * sizeof(row_t));
  if (!tb->rows) {
    for (size_t i = 0; i < col_len; i++) {
      free(tb->columns[i].name);
    }
    free(tb->columns);
    free(tb->name);
    return -5;
  }
  
  tb->rows_len = 0;
  tb->row_cap = init_row_cap;
  db->tbls_len++;
  return 0;
}

static int deleteTable(db_t *db, size_t idx) {
  if (!db || idx >= db->tbls_len)
    return -1;

  freeTableContents(&db->tables[idx]);

  for (size_t i = idx; i < db->tbls_len - 1; i++) {
    db->tables[i] = db->tables[i + 1];
  }

  db->tbls_len--;
  return 0;
}

/* ----------------------------------------------------------------------------- */

//create empty row
static row_t createEmptyRow(table_t *tb) {
  row_t row = {0}; 

  if (!tb || tb->cols_len == 0) {
    return row; 
  }

  row.len = tb->cols_len;
  row.values = malloc(sizeof(column_val_t) * tb->cols_len);
  if (!row.values) {
    row.len = 0; 
    return row;
  }

  for (size_t i = 0; i < tb->cols_len; i++) {
    row.values[i].ptr = NULL;
    row.values[i].size = 0;
  }

  for (size_t i = 0; i < tb->cols_len; i++) {
    size_t sz = type_size(tb->columns[i].type, tb->columns[i].len);
    row.values[i].size = sz;
    
    if (sz > 0) {
      row.values[i].ptr = malloc(sz);
      if (!row.values[i].ptr) {
        for (size_t j = 0; j < i; j++) {
          if (row.values[j].ptr) {
            free(row.values[j].ptr);
          }
        }
        free(row.values);
        row.len = 0;
        row.values = NULL;
        return row;
      }
      memset(row.values[i].ptr, 0, sz);
    }
  }

  return row;
}

static inline bool isValidRow(const row_t *row) {
  return row && row->len > 0 && row->values != NULL;
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
static int deleteRow(table_t *tb, size_t idx) {
  if (idx >= tb->rows_len) return -1;
  freeRowContents(tb, &tb->rows[idx]);
  for (size_t i = idx; i < tb->rows_len - 1; i++) {
    tb->rows[i] = tb->rows[i + 1];
  }
  tb->rows_len--;
  return 0;
}

/* ----------------------------------------------------------------------------- */

static inline void setInt(row_t *row, size_t idx, int val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((int*)row->values[idx].ptr) = val;
  }
}

static inline void setInt64(row_t *row, size_t idx, int64_t val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((int64_t*)row->values[idx].ptr) = val;
  }
}

static inline void setUint(row_t *row, size_t idx, uint32_t val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((uint32_t*)row->values[idx].ptr) = val;
  }
}

static inline void setUint64(row_t *row, size_t idx, uint64_t val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((uint64_t*)row->values[idx].ptr) = val;
  }
}

static inline void setBool(row_t *row, size_t idx, bool val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((bool*)row->values[idx].ptr) = val;
  }
}

static inline void setDouble(row_t *row, size_t idx, double val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((double*)row->values[idx].ptr) = val;
  }
}

static void setStr(row_t *row, size_t idx, const char *str) {
  if (idx >= row->len || !str) return;
  
  size_t len = strlen(str) + 1;

  if (row->values[idx].ptr) {
    free(row->values[idx].ptr);
  }

  row->values[idx].ptr = malloc(len);
  if (!row->values[idx].ptr) return;

  memcpy(row->values[idx].ptr, str, len);
  row->values[idx].size = len;
}

static void setCompactUUID(row_t *row, size_t idx, comp_uuid_t *val) {
  if (idx >= row->len || !val) return;
  
  if (!row->values[idx].ptr) {
    row->values[idx].ptr = malloc(sizeof(comp_uuid_t));
    if (!row->values[idx].ptr) return;
  }

  comp_uuid_t *dest = (comp_uuid_t *)row->values[idx].ptr;

  if (dest->raw) {
    free(dest->raw);
  }
  
  dest->raw = malloc(COMPUUID_LEN);
  if (!dest->raw) return;
  
  memcpy(dest->raw, val->raw, COMPUUID_LEN);
}

/* ----------------------------------------------------------------------------- */

static comp_uuid_t *generateCompUUID(void) {
  comp_uuid_t *c_uuid = malloc(sizeof(comp_uuid_t));
  if (!c_uuid) return NULL;

  c_uuid->raw = malloc(COMPUUID_LEN);
  if (!c_uuid->raw) {
    free(c_uuid);
    return NULL;
  }

  uint32_t ts = (uint32_t)time(NULL);
  uint32_t be_ts = htonl(ts);
  memcpy(c_uuid->raw, &be_ts, 4); 
  c_uuid->raw[4] = COMPUUID_VERSION;

  for (int i = 0; i < 11; i++) {
    c_uuid->raw[5 + i] = (unsigned char)(arc4random() & 0xFF);
  }

  return c_uuid;
}

/* ----------------------------------------------------------------------------- */

int main() {
    db_t *db = createDatabase("mydb", 4);
    if (!db) return 1;

    column_t cols[2];
    cols[0].name = "id"; cols[0].type = COL_INT; cols[0].nullable = false; cols[0].len = 0;
    cols[1].name = "name"; cols[1].type = COL_STR; cols[1].nullable = false; cols[1].len = 0;

    if (createTable(db, "users", cols, 2, 4) != 0) {
        printf("Failed to create table\n");
        freeDatabase(db);
        return 1;
    }

    table_t *tb = &db->tables[db->tbls_len - 1];

    row_t r = createEmptyRow(tb);
    setInt(&r, 0, 42);
    setStr(&r, 1, "Alice");
    insertRow(tb, r);

    row_t r2 = createEmptyRow(tb);
    setInt(&r2, 0, 7);
    setStr(&r2, 1, "Bob");
    insertRow(tb, r2);

    // Print DB info
    printf("Database: %s\n", db->name);
    for (size_t t = 0; t < db->tbls_len; t++) {
        table_t *tbl = &db->tables[t];
        printf(" Table: %s\n", tbl->name);
        printf("  Columns: ");
        for (size_t c = 0; c < tbl->cols_len; c++) {
            printf("%s%s", tbl->columns[c].name, c < tbl->cols_len - 1 ? ", " : "\n");
        }

        for (size_t r = 0; r < tbl->rows_len; r++) {
            printf("  Row %zu: ", r);
            for (size_t c = 0; c < tbl->cols_len; c++) {
                column_val_t *val = &tbl->rows[r].values[c];
                switch(tbl->columns[c].type) {
                    case COL_INT: printf("%d", *((int*)val->ptr)); break;
                    case COL_INT64: printf("%" PRId64, *((int64_t*)val->ptr)); break;
                    case COL_UINT: printf("%u", *((uint32_t*)val->ptr)); break;
                    case COL_UINT64: printf("%" PRIu64, *((uint64_t*)val->ptr)); break;
                    case COL_FLOAT64: printf("%f", *((double*)val->ptr)); break;
                    case COL_STR: case COL_STRICT_STR: printf("%s", (char*)val->ptr); break;
                    case COL_BOOL: printf("%s", *((bool*)val->ptr) ? "true" : "false"); break;
                    default: printf("N/A"); break;
                }
                if (c < tbl->cols_len - 1) printf(", ");
            }
            printf("\n");
        }
    }

    freeDatabase(db);
    return 0;
}
