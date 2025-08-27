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

static int insertRowSafe(table_t *tb, row_t row) {
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
    
    size_t expected = type_size(col->type, col->len);
    if (expected > 0 && val->size != expected) {
      return DB_ERROR_COLUMN_MISMATCH;
    }
    
    switch (col->type) {
      case COL_CO_UUID: {
        comp_uuid_t *uuid = (comp_uuid_t*)val->ptr;
        if (!uuid || !uuid->raw) {
          return DB_ERROR_NULL_PARAM;
        }
        break;
      }
      case COL_STR:
      case COL_STRICT_STR: {
        if (col->type == COL_STRICT_STR && val->size > col->len) {
          return DB_ERROR_COLUMN_MISMATCH;
        }
        char *str = (char*)val->ptr;
        if (str[val->size - 1] != '\0') {
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

static inline void setByte(row_t *row, size_t idx, unsigned char val) {
  if (idx < row->len && row->values[idx].ptr) {
    *((unsigned char*)row->values[idx].ptr) = val;
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

static int getInt(const row_t *row, size_t idx, int *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((int*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getInt64(const row_t *row, size_t idx, int64_t *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((int64_t*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getUint(const row_t *row, size_t idx, uint32_t *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((uint32_t*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getUint64(const row_t *row, size_t idx, uint64_t *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((uint64_t*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getBool(const row_t *row, size_t idx, bool *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((bool*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getDouble(const row_t *row, size_t idx, double *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((double*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getByte(const row_t *row, size_t idx, unsigned char *out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = *((unsigned char*)row->values[idx].ptr);
  return DB_SUCCESS;
}

static int getString(const row_t *row, size_t idx, char **out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = (char*)row->values[idx].ptr;
  return DB_SUCCESS;
}

static int getCompactUUID(const row_t *row, size_t idx, comp_uuid_t **out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = (comp_uuid_t*)row->values[idx].ptr;
  return DB_SUCCESS;
}

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

static void printCompactUUID(comp_uuid_t *uuid) {
  if (!uuid || !uuid->raw) {
    printf("NULL");
    return;
  }
  
  uint32_t ts_be;
  memcpy(&ts_be, uuid->raw, 4);
  uint32_t timestamp = ntohl(ts_be);
  
  printf("%08x-%02x-", timestamp, uuid->raw[4]);
  for (int i = 5; i < COMPUUID_LEN; i++) {
    printf("%02x", uuid->raw[i]);
    if (i == 7 || i == 9) printf("-");
  }
}

int main() {
  printf("=== Testing In-Memory Database with Compact-UUID ===\n\n");
  
  db_t *db = createDatabase("test_db", 4);
  if (!db) {
    printf("Failed to create database\n");
    return 1;
  }
  printf("✓ Created database: %s\n", db->name);

  column_t cols[6];
  
  cols[0].name = strdup("id");
  cols[0].type = COL_CO_UUID;
  cols[0].nullable = false;
  cols[0].len = 0;
  
  cols[1].name = strdup("user_id");
  cols[1].type = COL_INT;
  cols[1].nullable = false;
  cols[1].len = 0;
  
  cols[2].name = strdup("name");
  cols[2].type = COL_STR;
  cols[2].nullable = false;
  cols[2].len = 0;
  
  cols[3].name = strdup("active");
  cols[3].type = COL_BOOL;
  cols[3].nullable = true;
  cols[3].len = 0;

  cols[4].name = strdup("score");
  cols[4].type = COL_FLOAT64;
  cols[4].nullable = true;
  cols[4].len = 0;

  cols[5].name = strdup("level");
  cols[5].type = COL_BYTE;
  cols[5].nullable = false;
  cols[5].len = 0;

  int result = createTable(db, "users", cols, 6, 8);
  if (result != 0) {
    printf("Failed to create table (error: %d)\n", result);
    for (int i = 0; i < 6; i++) {
      free(cols[i].name);
    }
    freeDatabase(db);
    return 1;
  }
  printf("✓ Created table: users\n");

  table_t *tb = &db->tables[0];

  printf("\n--- Test 1: Inserting valid rows ---\n");
  
  row_t r1 = createEmptyRow(tb);
  comp_uuid_t *uuid1 = generateCompUUID();
  if (!uuid1) {
    printf("Failed to generate UUID\n");
    goto cleanup;
  }
  
  setCompactUUID(&r1, 0, uuid1);
  setInt(&r1, 1, 1001);
  setStr(&r1, 2, "Alice Johnson");
  setBool(&r1, 3, true);
  setDouble(&r1, 4, 95.5);
  setByte(&r1, 5, 42);
  
  result = insertRowSafe(tb, r1);
  if (result == DB_SUCCESS) {
    printf("✓ Inserted Alice Johnson\n");
  } else {
    printf("✗ Failed to insert Alice (error: %d)\n", result);
  }

  row_t r2 = createEmptyRow(tb);
  comp_uuid_t *uuid2 = generateCompUUID();
  if (!uuid2) {
    printf("Failed to generate UUID\n");
    goto cleanup;
  }
  
  setCompactUUID(&r2, 0, uuid2);
  setInt(&r2, 1, 1002);
  setStr(&r2, 2, "Bob Smith");
  setByte(&r2, 5, 15);
  
  result = insertRowSafe(tb, r2);
  if (result == DB_SUCCESS) {
    printf("✓ Inserted Bob Smith (with null active/score)\n");
  } else {
    printf("✗ Failed to insert Bob (error: %d)\n", result);
  }

  row_t r3 = createEmptyRow(tb);
  comp_uuid_t *uuid3 = generateCompUUID();
  if (!uuid3) {
    printf("Failed to generate UUID\n");
    goto cleanup;
  }
  
  setCompactUUID(&r3, 0, uuid3);
  setInt(&r3, 1, 1003);
  setStr(&r3, 2, "Charlie Brown");
  setBool(&r3, 3, false);
  setDouble(&r3, 4, 78.3);
  setByte(&r3, 5, 255);
  
  result = insertRowSafe(tb, r3);
  if (result == DB_SUCCESS) {
    printf("✓ Inserted Charlie Brown\n");
  } else {
    printf("✗ Failed to insert Charlie (error: %d)\n", result);
  }

  printf("\n--- Test 2: Testing validation ---\n");
  row_t r4 = createEmptyRow(tb);
  comp_uuid_t *uuid4 = generateCompUUID();
  if (uuid4) {
    setCompactUUID(&r4, 0, uuid4);
    setInt(&r4, 1, 1004);
    setBool(&r4, 3, true);
    setByte(&r4, 5, 10);
    
    result = insertRowSafe(tb, r4);
    if (result != DB_SUCCESS) {
      printf("✓ Correctly rejected row with missing required field (error: %d)\n", result);
    } else {
      printf("✗ Should have rejected invalid row\n");
    }
    
    freeRowContents(tb, &r4);
    free(uuid4->raw);
    free(uuid4);
  }

  printf("\n--- Database Contents ---\n");
  printf("Database: %s\n", db->name);
  printf("Table: %s (%zu rows)\n", tb->name, tb->rows_len);
  printf("Columns: ");
  for (size_t c = 0; c < tb->cols_len; c++) {
    printf("%s%s", tb->columns[c].name, c < tb->cols_len - 1 ? ", " : "\n");
  }
  printf("\n");

  for (size_t r = 0; r < tb->rows_len; r++) {
    printf("Row %zu:\n", r + 1);
    
    comp_uuid_t *uuid;
    if (getCompactUUID(&tb->rows[r], 0, &uuid) == 0) {
      printf("  ID: ");
      printCompactUUID(uuid);
      printf("\n");
    }
    
    int user_id;
    if (getInt(&tb->rows[r], 1, &user_id) == 0) {
      printf("  User ID: %d\n", user_id);
    }
    
    char *name;
    if (getString(&tb->rows[r], 2, &name) == 0) {
      printf("  Name: %s\n", name);
    }
    
    if (tb->rows[r].values[3].ptr) {
      bool active;
      if (getBool(&tb->rows[r], 3, &active) == 0) {
        printf("  Active: %s\n", active ? "true" : "false");
      }
    } else {
      printf("  Active: NULL\n");
    }

    if (tb->rows[r].values[4].ptr) {
      double score;
      if (getDouble(&tb->rows[r], 4, &score) == 0) {
        printf("  Score: %.1f\n", score);
      }
    } else {
      printf("  Score: NULL\n");
    }

    unsigned char level;
    if (getByte(&tb->rows[r], 5, &level) == 0) {
      printf("  Level: %u\n", level);
    }
    
    printf("\n");
  }

  printf("--- Performance Test ---\n");
  clock_t start = clock();
  
  for (int i = 0; i < 1000; i++) {
    row_t perf_row = createEmptyRow(tb);
    comp_uuid_t *perf_uuid = generateCompUUID();
    if (!perf_uuid) break;
    
    setCompactUUID(&perf_row, 0, perf_uuid);
    setInt(&perf_row, 1, 2000 + i);
    
    char temp_name[50];
    snprintf(temp_name, sizeof(temp_name), "TestUser_%d", i);
    setStr(&perf_row, 2, temp_name);
    setBool(&perf_row, 3, i % 2 == 0);
    setDouble(&perf_row, 4, 50.0 + (i % 100));
    setByte(&perf_row, 5, i % 256);
    
    if (insertRowSafe(tb, perf_row) != DB_SUCCESS) {
      freeRowContents(tb, &perf_row);
      free(perf_uuid->raw);
      free(perf_uuid);
      break;
    }
    free(perf_uuid->raw);
    free(perf_uuid);
  }
  
  clock_t end = clock();
  double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("✓ Inserted 1000 additional rows in %.3f seconds\n", cpu_time);
  printf("✓ Total rows: %zu\n", tb->rows_len);

cleanup:
  for (int i = 0; i < 6; i++) {
    if (cols[i].name) {
      free(cols[i].name);
    }
  }

  if (uuid1) { free(uuid1->raw); free(uuid1); }
  if (uuid2) { free(uuid2->raw); free(uuid2); }
  if (uuid3) { free(uuid3->raw); free(uuid3); }

  freeDatabase(db);
  
  printf("\n=== Test completed successfully ===\n");
  return 0;
}
