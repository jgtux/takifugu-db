#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
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
  DB_ERROR_INVALID_INDEX = -6,
  DB_ERROR_IN_USAGE = -7,
  DB_ERROR_NOT_FOUND = -8
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
  atomic_int ref_count;
  atomic_bool marked_for_del;  // FIXED: Use atomic bool
  pthread_mutex_t tbl_mutex;
  size_t table_index;  // FIXED: Add table index for proper reference management
} table_t;

typedef struct database {
  char *name;
  table_t *tables;
  size_t tbls_len;
  size_t table_cap;
  pthread_mutex_t db_mutex;
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
  case COL_DYNAMIC_STR: return len;
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

/* ---------------------------db_functions-------------------------------- */

static db_t *createDatabase(const char *name, size_t init_table_cap) {
  if (!name)
    return NULL;

  db_t *db = malloc(sizeof(db_t));
  if (!db)
    return NULL;

  if (pthread_mutex_init(&db->db_mutex, NULL) != 0) {
    free(db);
    return NULL;
  }

  db->name = strdup(name);
  if (!db->name) {
    pthread_mutex_destroy(&db->db_mutex);
    free(db);
    return NULL;
  }

  db->tbls_len = 0;
  db->table_cap = init_table_cap ? init_table_cap : 1;
  db->tables = malloc(db->table_cap * sizeof(table_t));
  if (!db->tables) {
    free(db->name);
    pthread_mutex_destroy(&db->db_mutex);
    free(db);
    return NULL;
  }
  return db;
}

static int deleteDatabase(db_t *db) {
  if (!db) return DB_ERROR_NULL_PARAM;

  pthread_mutex_lock(&db->db_mutex);

  if (db->tables && db->tbls_len > 0) {
    for (size_t i = 0; i < db->tbls_len; i++) {
      // FIXED: Mark table for deletion first
      atomic_store(&db->tables[i].marked_for_del, true);
      
      // Wait for all references to be released
      while (atomic_load(&db->tables[i].ref_count) > 0) {
        pthread_mutex_unlock(&db->db_mutex);
        usleep(1000); // Brief sleep
        pthread_mutex_lock(&db->db_mutex);
      }
      
      freeTableContents(&db->tables[i]);
      pthread_mutex_destroy(&db->tables[i].tbl_mutex);
    }
  }

  pthread_mutex_unlock(&db->db_mutex);
  pthread_mutex_destroy(&db->db_mutex);
  freeDatabase(db);
  return DB_SUCCESS;
}

/* ---------------------------table_functions-------------------------------- */

// FIXED: Proper table reference management
static table_t* acquireTableRef(db_t *db, size_t idx) {
    if (!db || idx >= db->tbls_len) return NULL;
    
    pthread_mutex_lock(&db->db_mutex);
    if (idx >= db->tbls_len) {
        pthread_mutex_unlock(&db->db_mutex);
        return NULL;
    }
    
    table_t *tb = &db->tables[idx];
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&db->db_mutex);
        return NULL;
    }
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_unlock(&db->db_mutex);
    return tb;
}

// Helper function to release table reference
static void releaseTableRef(table_t *tb) {
    if (tb) {
        atomic_fetch_sub(&tb->ref_count, 1);
    }
}

// FIXED: Enhanced deleteTable with proper reference counting
static int deleteTable(db_t *db, size_t idx) {
    if (!db) return DB_ERROR_NULL_PARAM;
    
    pthread_mutex_lock(&db->db_mutex);
    
    if (idx >= db->tbls_len) {
        pthread_mutex_unlock(&db->db_mutex);
        return DB_ERROR_INVALID_INDEX;
    }

    table_t *tb = &db->tables[idx];
    
    // Mark for deletion first
    atomic_store(&tb->marked_for_del, true);
    
    // Wait for all references to be released
    while (atomic_load(&tb->ref_count) > 0) {
        pthread_mutex_unlock(&db->db_mutex);
        usleep(1000);
        pthread_mutex_lock(&db->db_mutex);
        
        // Re-check if table still exists after re-acquiring lock
        if (idx >= db->tbls_len) {
            pthread_mutex_unlock(&db->db_mutex);
            return DB_ERROR_INVALID_INDEX;
        }
    }
    
    // Now safe to delete
    pthread_mutex_lock(&tb->tbl_mutex);
    freeTableContents(tb);
    pthread_mutex_unlock(&tb->tbl_mutex);
    pthread_mutex_destroy(&tb->tbl_mutex);

    // Shift remaining tables and update their indices
    for (size_t i = idx; i < db->tbls_len - 1; i++) {
        db->tables[i] = db->tables[i + 1];
        db->tables[i].table_index = i;  // FIXED: Update table index
    }

    db->tbls_len--;
    pthread_mutex_unlock(&db->db_mutex);
    return DB_SUCCESS;
}

// FIXED: Enhanced createTable with proper initialization
static int createTable(db_t *db, const char *name, column_t *columns,
                       size_t col_len, size_t init_row_cap) {
    if (!db || !columns || col_len == 0 || !name)
        return DB_ERROR_NULL_PARAM;
    
    pthread_mutex_lock(&db->db_mutex);
    
    // Check for duplicate name
    for (size_t i = 0; i < db->tbls_len; i++) {
        if (db->tables[i].name && strcmp(db->tables[i].name, name) == 0) {
            pthread_mutex_unlock(&db->db_mutex);
            return DB_ERROR_DUPLICATE_NAME;
        }
    }
    
    if (db->tbls_len >= db->table_cap) {
        size_t new_cap = db->table_cap * 2;
        table_t *new_tables = realloc(db->tables, new_cap * sizeof(table_t));
        if (!new_tables) {
            pthread_mutex_unlock(&db->db_mutex);
            return DB_ERROR_OUT_OF_MEMORY;
        }
        db->tables = new_tables;
        db->table_cap = new_cap;
    }
    
    table_t *tb = &db->tables[db->tbls_len];
    memset(tb, 0, sizeof(table_t));
    
    if (pthread_mutex_init(&tb->tbl_mutex, NULL) != 0) {
        pthread_mutex_unlock(&db->db_mutex);
        return DB_ERROR_OUT_OF_MEMORY;
    }
    
    // FIXED: Initialize reference count and mark for deletion flag properly
    atomic_store(&tb->ref_count, 0);  // Start with 0, acquire when needed
    atomic_store(&tb->marked_for_del, false);
    tb->table_index = db->tbls_len;  // FIXED: Set table index
    
    tb->name = strdup(name);
    if (!tb->name) {
        pthread_mutex_destroy(&tb->tbl_mutex);
        pthread_mutex_unlock(&db->db_mutex);
        return DB_ERROR_OUT_OF_MEMORY;
    }
        
    tb->columns = malloc(col_len * sizeof(column_t));
    if (!tb->columns) {
        free(tb->name);
        pthread_mutex_destroy(&tb->tbl_mutex);
        pthread_mutex_unlock(&db->db_mutex);
        return DB_ERROR_OUT_OF_MEMORY;
    }
    
    // Copy column definitions
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
                pthread_mutex_destroy(&tb->tbl_mutex);
                pthread_mutex_unlock(&db->db_mutex);
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
        pthread_mutex_destroy(&tb->tbl_mutex);
        pthread_mutex_unlock(&db->db_mutex);
        return DB_ERROR_OUT_OF_MEMORY;
    }
    
    tb->rows_len = 0;
    tb->row_cap = init_row_cap;
    db->tbls_len++;
    
    pthread_mutex_unlock(&db->db_mutex);
    return DB_SUCCESS;
}

/* ---------------------------row_functions-------------------------------- */

static int createEmptyRow(table_t *tb, row_t *row) {
  if (!tb || tb->cols_len == 0) {
    return DB_ERROR_NULL_PARAM; 
  }

  // FIXED: Check if table is marked for deletion
  if (atomic_load(&tb->marked_for_del)) {
    return DB_ERROR_TABLE_NOT_FOUND;
  }

  // FIXED: Acquire reference before locking
  atomic_fetch_add(&tb->ref_count, 1);
  pthread_mutex_lock(&tb->tbl_mutex);

  // FIXED: Double-check after acquiring lock
  if (atomic_load(&tb->marked_for_del)) {
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_ERROR_TABLE_NOT_FOUND;
  }

  row->len = tb->cols_len;
  row->values = malloc(sizeof(column_val_t) * tb->cols_len);
  if (!row->values) {
    row->len = 0; 
    atomic_fetch_sub(&tb->ref_count, 1);
    pthread_mutex_unlock(&tb->tbl_mutex);
    return DB_ERROR_OUT_OF_MEMORY;
  }

  // FIXED: Initialize all pointers first
  for (size_t i = 0; i < tb->cols_len; i++) {
    row->values[i].ptr = NULL;
    row->values[i].size = 0;
  }

  // FIXED: Then allocate memory with proper cleanup
  for (size_t i = 0; i < tb->cols_len; i++) {
    size_t sz = typeSize(tb->columns[i].type, tb->columns[i].len);
    row->values[i].size = sz;
    
    if (sz > 0) {
      row->values[i].ptr = malloc(sz);
      if (!row->values[i].ptr) {
        // FIXED: Cleanup ALL allocated memory including current index
        for (size_t j = 0; j < i; j++) {
          if (row->values[j].ptr) {
            free(row->values[j].ptr);
            row->values[j].ptr = NULL;
          }
        }
        free(row->values);
        row->values = NULL;
        row->len = 0;
        atomic_fetch_sub(&tb->ref_count, 1);
        pthread_mutex_unlock(&tb->tbl_mutex);
        return DB_ERROR_OUT_OF_MEMORY;
      }
      memset(row->values[i].ptr, 0, sz);
    }
  }

  atomic_fetch_sub(&tb->ref_count, 1);
  pthread_mutex_unlock(&tb->tbl_mutex);
  return DB_SUCCESS;
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

// FIXED: Improved insertRow with proper reference management
static int insertRow(db_t *db, size_t table_idx, row_t row) {
    if (!db || !isValidRow(&row)) {
        return DB_ERROR_NULL_PARAM;
    }

    // Acquire reference to prevent deletion during operation
    table_t *tb = acquireTableRef(db, table_idx);
    if (!tb) {
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    pthread_mutex_lock(&tb->tbl_mutex);

    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        releaseTableRef(tb);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    if (row.len != tb->cols_len) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        releaseTableRef(tb);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    // Validation logic
    for (size_t i = 0; i < tb->cols_len; i++) {
        column_t *col = &tb->columns[i];
        column_val_t *val = &row.values[i];

        if (!col->nullable && !val->ptr) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            releaseTableRef(tb);
            return DB_ERROR_NULL_PARAM;
        }

        if (!val->ptr) continue;

        if (col->type == COL_DYNAMIC_STR || col->type == COL_STRICT_STR) {
            int result = validateStringInInsertRow(tb, &row, i);
            if (result != DB_SUCCESS) {
                pthread_mutex_unlock(&tb->tbl_mutex);
                releaseTableRef(tb);
                return result;
            }
            continue;
        }

        size_t expected = typeSize(col->type, col->len);
        if (expected > 0 && val->size != expected) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            releaseTableRef(tb);
            return DB_ERROR_COLUMN_MISMATCH;
        }
    }

    // Expand capacity if needed
    if (tb->rows_len >= tb->row_cap) {
        size_t new_cap = tb->row_cap ? tb->row_cap * 2 : 4;
        row_t *new_rows = realloc(tb->rows, new_cap * sizeof(row_t));
        if (!new_rows) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            releaseTableRef(tb);
            return DB_ERROR_OUT_OF_MEMORY;
        }
        tb->rows = new_rows;
        tb->row_cap = new_cap;
    }

    tb->rows[tb->rows_len++] = row;
    pthread_mutex_unlock(&tb->tbl_mutex);
    releaseTableRef(tb);
    return DB_SUCCESS;
}

static int deleteRow(table_t *tb, size_t idx) {
  if (!tb)
    return DB_ERROR_NULL_PARAM;

  // FIXED: Acquire reference before locking
  atomic_fetch_add(&tb->ref_count, 1);
  pthread_mutex_lock(&tb->tbl_mutex);

  if (atomic_load(&tb->marked_for_del)) {
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_ERROR_TABLE_NOT_FOUND;
  }

  if (idx >= tb->rows_len) {
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_ERROR_INVALID_INDEX;
  }

  freeRowContents(tb, &tb->rows[idx]);

  for (size_t i = idx; i < tb->rows_len - 1; i++) {
    tb->rows[i] = tb->rows[i + 1];
  }

  tb->rows_len--;
  pthread_mutex_unlock(&tb->tbl_mutex);
  atomic_fetch_sub(&tb->ref_count, 1);
  return DB_SUCCESS;
}

/* ---------------------------set_val_functions-------------------------------- */

// FIXED: All setter functions now properly handle thread safety
static int setInt(table_t *tb, row_t *row, size_t idx, const int *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_INT) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((int*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

// Similar pattern applies to all other setter functions
static int setStr(table_t *tb, row_t *row, size_t idx, const char *str) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) 
        return DB_ERROR_INVALID_INDEX;
    
    // FIXED: Proper thread safety with reference counting
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    
    if (col->type != COL_DYNAMIC_STR && col->type != COL_STRICT_STR) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }
    
    if (!str) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }
    
    // FIXED: Validate string doesn't contain embedded nulls and length
    size_t str_len = 0;
    size_t max_check = (col->type == COL_DYNAMIC_STR) ? col->len : col->len - 1;
    
    // Count actual length and check for embedded nulls
    while (str_len <= max_check && str[str_len] != '\0') {
        str_len++;
    }
    
    if (str_len > max_check) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }
    
    if (col->type == COL_DYNAMIC_STR) {
        if (cell->ptr) {
            free(cell->ptr);
        }
        cell->size = str_len + 1;
        cell->ptr = malloc(cell->size);
        if (!cell->ptr) { 
            cell->size = 0;
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_OUT_OF_MEMORY; 
        }
        memcpy(cell->ptr, str, str_len);
        ((char*)cell->ptr)[str_len] = '\0'; // FIXED: Ensure null termination
    } else { // COL_STRICT_STR
      if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
      }

      // ✅ STRICT_STR deve ser exatamente col->len - 1
      if (str_len != col->len - 1) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
      }

      // FIXED: Safe copy
      memset(cell->ptr, 0, col->len);  // garante preenchimento completo
      memcpy(cell->ptr, str, str_len); // copia exatamente col->len - 1
      cell->size = col->len;           // inclui terminador nulo
    }

    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

// FIXED: Add missing setter functions for completeness
static int setInt64(table_t *tb, row_t *row, size_t idx, const int64_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_INT64) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((int64_t*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

static int setUint(table_t *tb, row_t *row, size_t idx, const uint32_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_UINT) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((uint32_t*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

static int setUint64(table_t *tb, row_t *row, size_t idx, const uint64_t *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_UINT64) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((uint64_t*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

static int setBool(table_t *tb, row_t *row, size_t idx, const bool *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_BOOL) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((bool*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

static int setDouble(table_t *tb, row_t *row, size_t idx, const double *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_FLOAT64) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((double*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

static int setByte(table_t *tb, row_t *row, size_t idx, const unsigned char *val) {
    if (!tb || !row || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;
    
    atomic_fetch_add(&tb->ref_count, 1);
    pthread_mutex_lock(&tb->tbl_mutex);
    
    if (atomic_load(&tb->marked_for_del)) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }
    
    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];
    if (col->type != COL_BYTE) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!val) {
        if (!col->nullable) {
            pthread_mutex_unlock(&tb->tbl_mutex);
            atomic_fetch_sub(&tb->ref_count, 1);
            return DB_ERROR_NULL_PARAM;
        }
        if (cell->ptr) {
            free(cell->ptr);
            cell->ptr = NULL;
        }
        cell->size = 0;
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_SUCCESS;
    }

    if (!cell->ptr) {
        pthread_mutex_unlock(&tb->tbl_mutex);
        atomic_fetch_sub(&tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }
    *((unsigned char*)cell->ptr) = *val;
    
    pthread_mutex_unlock(&tb->tbl_mutex);
    atomic_fetch_sub(&tb->ref_count, 1);
    return DB_SUCCESS;
}

/* ---------------------------get_val_functions-------------------------------- */

// FIXED: Thread-safe getter functions
static int getInt(const table_t *tb, const row_t *row, size_t idx, int *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    // FIXED: Const cast needed for atomic operations - use careful approach
    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_INT) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((int*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getInt64(const table_t *tb, const row_t *row, size_t idx, int64_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_INT64) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((int64_t*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getUint(const table_t *tb, const row_t *row, size_t idx, uint32_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_UINT) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((uint32_t*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getUint64(const table_t *tb, const row_t *row, size_t idx, uint64_t *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_UINT64) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((uint64_t*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getBool(const table_t *tb, const row_t *row, size_t idx, bool *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_BOOL) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((bool*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getDouble(const table_t *tb, const row_t *row, size_t idx, double *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_FLOAT64) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((double*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getByte(const table_t *tb, const row_t *row, size_t idx, unsigned char *out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_BYTE) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = *((unsigned char*)cell->ptr);
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_SUCCESS;
}

static int getStr(const table_t *tb, const row_t *row, size_t idx, 
                  char **out, size_t *out_len, bool *is_null) {
  if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

  table_t *mutable_tb = (table_t*)tb;
  atomic_fetch_add(&mutable_tb->ref_count, 1);
    
  if (atomic_load(&tb->marked_for_del)) {
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_ERROR_TABLE_NOT_FOUND;
  }

  column_t *col = &tb->columns[idx];
  column_val_t *cell = &row->values[idx];

  if (col->type != COL_DYNAMIC_STR && col->type != COL_STRICT_STR) {
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_ERROR_COLUMN_MISMATCH;
  }

  if (!cell->ptr) {
    if (col->nullable) { 
      if (is_null) *is_null = true; 
      *out = NULL; 
      if (out_len) *out_len = 0;
      atomic_fetch_sub(&mutable_tb->ref_count, 1);
      return DB_SUCCESS; 
    }
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
    return DB_ERROR_NULL_PARAM;
  }

  if (is_null) *is_null = false;
  *out = (char*)cell->ptr;

  if (out_len) {
    if (col->type == COL_DYNAMIC_STR) {
      *out_len = strlen((char*)cell->ptr);  // 🔹 tamanho real
    } else { 
      *out_len = col->len - 1;              // 🔹 tamanho fixo definido
    }
  }

  atomic_fetch_sub(&mutable_tb->ref_count, 1);
  return DB_SUCCESS;
}

static int getFuguID(const table_t *tb, const row_t *row, size_t idx, fugu_id_t **out, bool *is_null) {
    if (!tb || !row || !out || idx >= row->len || idx >= tb->cols_len) return DB_ERROR_INVALID_INDEX;

    table_t *mutable_tb = (table_t*)tb;
    atomic_fetch_add(&mutable_tb->ref_count, 1);
    
    if (atomic_load(&tb->marked_for_del)) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_TABLE_NOT_FOUND;
    }

    column_t *col = &tb->columns[idx];
    column_val_t *cell = &row->values[idx];

    if (col->type != COL_FUGU_ID) {
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_COLUMN_MISMATCH;
    }

    if (!cell->ptr) {
        if (col->nullable) { 
            if (is_null) *is_null = true; 
            *out = NULL; 
            atomic_fetch_sub(&mutable_tb->ref_count, 1);
            return DB_SUCCESS; 
        }
        atomic_fetch_sub(&mutable_tb->ref_count, 1);
        return DB_ERROR_NULL_PARAM;
    }

    if (is_null) *is_null = false;
    *out = (fugu_id_t*)cell->ptr;
    atomic_fetch_sub(&mutable_tb->ref_count, 1);
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

    // FIXED: Use nanosecond precision for better uniqueness
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
    
    // FIXED: Mix in more randomness to avoid collisions
    uint16_t seq = (uint16_t)atomic_fetch_add(&g_sequence_counter, 1);
    
    // If sequence wraps, add microsecond delay to ensure different timestamp
    if (seq == 0) {
        usleep(1);
        gettimeofday(&tv, NULL);
        ts_us = (uint64_t)tv.tv_sec * 1000000ull + tv.tv_usec;
    }

    // Layout: [6 ts][2 machine_hash][1 proc][2 seq][1 ver]
    for (int i = 5; i >= 0; i--) {
        id.data[i] = (unsigned char)(ts_us & 0xFF);
        ts_us >>= 8;
    }

    id.data[6] = (g_machine_hash >> 8) & 0xFF;
    id.data[7] = g_machine_hash & 0xFF;
    id.data[8] = g_proc_hash;
    id.data[9]  = (seq >> 8) & 0xFF;
    id.data[10] = seq & 0xFF;
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
