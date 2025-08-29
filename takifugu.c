#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>

/* ---------------------------definitions-------------------------------- */

#define FUGUID_LEN 12
#define FUGUID_VERSION 0xF1

typedef enum {
  DB_SUCCESS = 0,
  DB_ERROR_NULL_PARAM = -1,
  DB_ERROR_OUT_OF_MEMORY = -2,
  DB_ERROR_TABLE_NOT_FOUND = -3,
  DB_ERROR_COLUMN_MISMATCH = -4,
  DB_ERROR_DUPLICATE_NAME = -5,
  DB_ERROR_INVALID_INDEX = -6
} int_return_type;

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

typedef struct fugu_id {
  unsigned char data[FUGUID_LEN];
} fugu_id_t;

static atomic_uint g_sequence_counter = 0;
static atomic_uint_least16_t g_machine_hash = 0;
static atomic_uint_least8_t  g_proc_hash = 0;

static inline size_t typeSize(col_type type, size_t len) {
  switch(type) {
  case COL_INT: return sizeof(int);
  case COL_INT64: return sizeof(int64_t);
  case COL_UINT: return sizeof(uint32_t);
  case COL_UINT64: return sizeof(uint64_t);
  case COL_FLOAT64: return sizeof(double);
  case COL_STRICT_STR: return len;
  case COL_BOOL: return sizeof(bool);
  case COL_BYTE: return sizeof(unsigned char);
  case COL_FUGU_ID: return sizeof(fugu_id_t);
  case COL_DYNAMIC_STR: return 0;
  default: return 0;
  }
}

/* ---------------------------free_functions-------------------------------- */

static void freeCell(col_type type, column_val_t *cell) {
  if (!cell) {
    return;
  }
  
  if (cell->ptr) {
    free(cell->ptr); 
    cell->ptr = NULL;
  }
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
    for (size_t i = 0; i < tb->rows_len && i < tb->cols_len; i++) {
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

/* ---------------------------db_functions-------------------------------- */

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
  if (!db) return DB_ERROR_NULL_PARAM;
  freeDatabase(db);
  return DB_SUCCESS;
}

/* ---------------------------table_functions-------------------------------- */

static int createTable(db_t *db, const char *name, column_t *columns,
                       size_t col_len, size_t init_row_cap) {
  if (!db || !columns || col_len == 0 || !name)
    return DB_ERROR_NULL_PARAM;
    
  if (db->tbls_len >= db->table_cap) {
    size_t new_cap = db->table_cap * 2;
    table_t *new_tables = realloc(db->tables, new_cap * sizeof(table_t));
    if (!new_tables)
      return DB_ERROR_OUT_OF_MEMORY;
    db->tables = new_tables;
    db->table_cap = new_cap;
  }
  
  table_t *tb = &db->tables[db->tbls_len];
  memset(tb, 0, sizeof(table_t));
  
  tb->name = strdup(name);
  if (!tb->name)
    return DB_ERROR_OUT_OF_MEMORY;
    
  tb->columns = malloc(col_len * sizeof(column_t));
  if (!tb->columns) {
    free(tb->name);
    return DB_ERROR_OUT_OF_MEMORY;
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
        return DB_ERROR_OUT_OF_MEMORY;
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
    return DB_ERROR_OUT_OF_MEMORY;
  }
  
  tb->rows_len = 0;
  tb->row_cap = init_row_cap;
  db->tbls_len++;
  return DB_SUCCESS;
}

static int deleteTable(db_t *db, size_t idx) {
  if (!db) return DB_ERROR_NULL_PARAM;
  if (idx >= db->tbls_len) return DB_ERROR_INVALID_INDEX;

  freeTableContents(&db->tables[idx]);

  for (size_t i = idx; i < db->tbls_len - 1; i++) {
    db->tables[i] = db->tables[i + 1];
  }

  db->tbls_len--;
  return DB_SUCCESS;
}

/* ---------------------------row_functions-------------------------------- */


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
    size_t sz = typeSize(tb->columns[i].type, tb->columns[i].len);
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

static int validateStringInInsertRow(table_t *tb, row_t *row, size_t i) {
  column_t *col = &tb->columns[i];
  column_val_t *val = &row->values[i];
  
  if (col->type == COL_DYNAMIC_STR) {
    // Dynamic string validation
    if (!val->ptr) {
      return col->nullable ? DB_SUCCESS : DB_ERROR_NULL_PARAM;
    }
    
    char *str = (char*)val->ptr;
    size_t actual_len = strlen(str) + 1;
    if (actual_len != val->size) {
      return DB_ERROR_COLUMN_MISMATCH;
    }
    
  } else if (col->type == COL_STRICT_STR) {
    // Fixed-length string validation  
    if (!val->ptr) {
      return col->nullable ? DB_SUCCESS : DB_ERROR_NULL_PARAM;
    }
    
    if (val->size != col->len) {
      return DB_ERROR_COLUMN_MISMATCH;
    }
    
    char *str = (char*)val->ptr;
    // Ensure null termination within bounds
    bool has_null = false;
    for (size_t j = 0; j < col->len; j++) {
      if (str[j] == '\0') {
        has_null = true;
        break;
      }
    }
    if (!has_null) {
      return DB_ERROR_COLUMN_MISMATCH;
    }
  }
  
  return DB_SUCCESS;
}

static inline bool isValidRow(const row_t *row) {
  return row && row->len > 0 && row->values != NULL;
}

static int insertRow(table_t *tb, row_t row) {
  if (!tb || !isValidRow(&row)) {
    return DB_ERROR_NULL_PARAM;
  }

  if (row.len != tb->cols_len) {
    return DB_ERROR_COLUMN_MISMATCH;
  }

  for (size_t i = 0; i < tb->cols_len; i++) {
    column_t *col = &tb->columns[i];
    column_val_t *val = &row.values[i];

    if (!col->nullable && !val->ptr) {
      return DB_ERROR_NULL_PARAM;
    }

    if (!val->ptr) continue;

    if (col->type == COL_DYNAMIC_STR || col->type == COL_STRICT_STR) {
      int result = validateStringInInsertRow(tb, &row, i);
      if (result != DB_SUCCESS) return result;
      continue;
    }

    size_t expected = typeSize(col->type, col->len);
    if (expected > 0 && val->size != expected) {
      return DB_ERROR_COLUMN_MISMATCH;
    }

    switch (col->type) {
      case COL_FUGU_ID: {
        if (val->size != sizeof(fugu_id_t)) {
          return DB_ERROR_COLUMN_MISMATCH;
        }
        break;
      }
      default:
        break;
    }
  }

  if (tb->rows_len >= tb->row_cap) {
    size_t new_cap = tb->row_cap ? tb->row_cap * 2 : 4;
    row_t *new_rows = realloc(tb->rows, new_cap * sizeof(row_t));
    if (!new_rows) {
      return DB_ERROR_OUT_OF_MEMORY;
    }
    tb->rows = new_rows;
    tb->row_cap = new_cap;
  }

  tb->rows[tb->rows_len++] = row;
  return DB_SUCCESS;
}

static int deleteRow(table_t *tb, size_t idx) {
  if (!tb) return DB_ERROR_NULL_PARAM;
  if (idx >= tb->rows_len) return DB_ERROR_INVALID_INDEX;
  freeRowContents(tb, &tb->rows[idx]);
  for (size_t i = idx; i < tb->rows_len - 1; i++) {
    tb->rows[i] = tb->rows[i + 1];
  }
  tb->rows_len--;
  return DB_SUCCESS;
}

/* ---------------------------set_val_functions-------------------------------- */

static int setInt(table_t *tb, row_t *row, size_t idx, const int *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_INT) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((int*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setInt64(table_t *tb, row_t *row, size_t idx, const int64_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_INT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((int64_t*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setUint(table_t *tb, row_t *row, size_t idx, const uint32_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_UINT) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((uint32_t*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setUint64(table_t *tb, row_t *row, size_t idx, const uint64_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_UINT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((uint64_t*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setBool(table_t *tb, row_t *row, size_t idx, const bool *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_BOOL) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((bool*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setDouble(table_t *tb, row_t *row, size_t idx, const double *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_FLOAT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((double*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setByte(table_t *tb, row_t *row, size_t idx, const unsigned char *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_BYTE) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    *((unsigned char*)cell->ptr) = *val;
    return DB_SUCCESS;
}

static int setStr(table_t *tb, row_t *row, size_t idx, const char *str) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) 
        return DB_ERROR_INVALID_INDEX;
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    
    if (col->type != COL_DYNAMIC_STR && col->type != COL_STRICT_STR) 
        return DB_ERROR_COLUMN_MISMATCH;
    
    if (!str) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }
    
    size_t str_len = strlen(str);
    
    if (col->type == COL_DYNAMIC_STR) {
        if (str_len > col->len) {
            return DB_ERROR_COLUMN_MISMATCH;
        }
        
        if (cell->ptr) {
            free(cell->ptr);
        }
        cell->size = str_len + 1;
        cell->ptr = malloc(cell->size);
        if (!cell->ptr) { 
            cell->size = 0; 
            return DB_ERROR_OUT_OF_MEMORY; 
        }
        memcpy(cell->ptr, str, str_len + 1);
    } else { // COL_STRICT_STR
        if (!cell->ptr) return DB_ERROR_NULL_PARAM;
        
        if (str_len >= col->len) {
            return DB_ERROR_COLUMN_MISMATCH;
        }
        
        for (size_t i = 0; i < col->len; i++) {
            if (i < str_len) {
                ((char*)cell->ptr)[i] = str[i];
            } else {
                ((char*)cell->ptr)[i] = '\0';
            }
        }
        cell->size = col->len;
    }
    
    return DB_SUCCESS;
}

static int setFuguID(table_t *tb, row_t *row, size_t idx, const fugu_id_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_FUGU_ID) return DB_ERROR_COLUMN_MISMATCH;

    if (!val) {
        if (!col->nullable) return DB_ERROR_NULL_PARAM;
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        return DB_SUCCESS;
    }

    if (!cell->ptr) return DB_ERROR_NULL_PARAM;
    memcpy(cell->ptr, val, sizeof(fugu_id_t));
    return DB_SUCCESS;
}

/* ---------------------------get_val_functions-------------------------------- */


static int getInt(const table_t *tb, const row_t *row, size_t idx, int *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_INT) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((int*)cell->ptr);
    return DB_SUCCESS;
}

static int getInt64(const table_t *tb, const row_t *row, size_t idx, int64_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_INT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((int64_t*)cell->ptr);
    return DB_SUCCESS;
}

static int getUint(const table_t *tb, const row_t *row, size_t idx, uint32_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_UINT) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((uint32_t*)cell->ptr);
    return DB_SUCCESS;
}

static int getUint64(const table_t *tb, const row_t *row, size_t idx, uint64_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_UINT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((uint64_t*)cell->ptr);
    return DB_SUCCESS;
}

static int getBool(const table_t *tb, const row_t *row, size_t idx, bool *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_BOOL) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((bool*)cell->ptr);
    return DB_SUCCESS;
}

static int getDouble(const table_t *tb, const row_t *row, size_t idx, double *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_FLOAT64) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((double*)cell->ptr);
    return DB_SUCCESS;
}

static int getByte(const table_t *tb, const row_t *row, size_t idx, unsigned char *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_BYTE) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { if (is_null) *is_null = true; return DB_SUCCESS; }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((unsigned char*)cell->ptr);
    return DB_SUCCESS;
}

static int getString(const table_t *tb, const row_t *row, size_t idx, char **out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_DYNAMIC_STR && col->type != COL_STRICT_STR) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            *out = NULL; 
            return DB_SUCCESS; 
        }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = (char*)cell->ptr;
    return DB_SUCCESS;
}

static int getFuguID(const table_t *tb, const row_t *row, size_t idx, fugu_id_t **out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_FUGU_ID) return DB_ERROR_COLUMN_MISMATCH;

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            *out = NULL; 
            return DB_SUCCESS; 
        }
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = (fugu_id_t*)cell->ptr;
    return DB_SUCCESS;
}

/* ---------------------------fuguid_functions-------------------------------- */


static uint16_t compute_machine_hash(void) {
    char host[256] = {0};
    gethostname(host, sizeof(host)-1);
    uint32_t h = 2166136261u;
    for (int i = 0; host[i]; i++) {
        h ^= (uint8_t)host[i];
        h *= 16777619u;
    }
    return (uint16_t)((h >> 16) ^ (h & 0xFFFF));
}

static void initFuguIDGenerator(void) {
  if (atomic_load(&g_machine_hash) == 0) {
    uint16_t expected = 0;
    uint16_t new_hash = compute_machine_hash();
    if (atomic_compare_exchange_strong(&g_machine_hash, &expected, new_hash)) {
      atomic_store(&g_proc_hash, (uint8_t)(getpid() & 0xFF));
    }
  }
}

static fugu_id_t generateFuguID(void) {
    fugu_id_t id;
    initFuguIDGenerator();

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ts_us = (uint64_t)tv.tv_sec * 1000000ull + tv.tv_usec;

    uint16_t seq = (uint16_t)atomic_fetch_add(&g_sequence_counter, 1);

    // Layout: [6 ts][2 machine_hash][1 proc][2 seq][1 ver]

    // 6 bytes timestamp BE
    for (int i = 5; i >= 0; i--) {
        id.data[i] = (unsigned char)(ts_us & 0xFF);
        ts_us >>= 8;
    }

    // 2 bytes machine hash
    id.data[6] = (g_machine_hash >> 8) & 0xFF;
    id.data[7] = g_machine_hash & 0xFF;

    // 1 byte process hash
    id.data[8] = g_proc_hash;

    // 2 bytes sequence BE
    id.data[9]  = (seq >> 8) & 0xFF;
    id.data[10] = seq & 0xFF;

    // 1 byte version
    id.data[11] = FUGUID_VERSION;

    return id;
}

static void printFuguID(const fugu_id_t *id) {
    if (!id) { printf("NULL"); return; }

    // decode timestamp
    uint64_t ts = 0;
    for (int i = 0; i < 6; i++) {
        ts = (ts << 8) | id->data[i];
    }
    uint16_t mh = (id->data[6] << 8) | id->data[7];
    uint8_t ph = id->data[8];
    uint16_t seq = (id->data[9] << 8) | id->data[10];
    uint8_t ver = id->data[11];

    printf("fugu:%012" PRIx64 "-%04x-%02x-%04x-%02x",
           ts, mh, ph, seq, ver);
}

uint64_t extractFuguIDTimestamp(const fugu_id_t *id) {
  if (!id) return 0;
  uint64_t ts = 0;
  for (int i = 0; i < 6; i++) {
    ts = (ts << 8) | id->data[i];
  }
  return ts;
}

int compareFuguID(const fugu_id_t *a, const fugu_id_t *b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  return memcmp(a->data, b->data, FUGUID_LEN);
}

// main is for testing

int main() {
   return 0;
}
