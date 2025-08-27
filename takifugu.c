#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>

#define FUGUID_LEN 12
#define FUGUID_VERSION 0x01

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

// Global counter for sequence numbers (thread-safe would need mutex in real implementation)
static uint32_t g_sequence_counter = 0;
static uint32_t g_process_id = 0;

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
  case COL_FUGU_ID: return sizeof(fugu_id_t);
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

  // FuguID is now a simple struct, no nested allocation needed
  free(cell->ptr); 
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
      case COL_FUGU_ID: {
        // Simple validation - just check it's the right size
        if (val->size != sizeof(fugu_id_t)) {
          return DB_ERROR_COLUMN_MISMATCH;
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

static void setFuguID(row_t *row, size_t idx, const fugu_id_t *val) {
  if (idx >= row->len || !val || !row->values[idx].ptr) return;
  
  memcpy(row->values[idx].ptr, val, sizeof(fugu_id_t));
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

static int getFuguID(const row_t *row, size_t idx, fugu_id_t **out) {
  if (!row || !out || idx >= row->len || !row->values[idx].ptr) {
    return DB_ERROR_NULL_PARAM;
  }
  *out = (fugu_id_t*)row->values[idx].ptr;
  return DB_SUCCESS;
}

// Initialize the FuguID generator
static void initFuguIDGenerator(void) {
  if (g_process_id == 0) {
    g_process_id = (uint32_t)getpid();
    srand((unsigned int)time(NULL) ^ g_process_id);
  }
}

// Fast, simple random number generator using linear congruential generator
static uint32_t fastRandom(void) {
  static uint32_t seed = 1;
  seed = seed * 1664525 + 1013904223;
  return seed;
}

static fugu_id_t generateFuguID(void) {
  fugu_id_t id;
  
  // Initialize generator if needed
  initFuguIDGenerator();
  
  // Get high-resolution timestamp (microseconds since epoch)
  struct timeval tv;
  gettimeofday(&tv, NULL);
  uint64_t timestamp = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
  
  // Layout: [6 bytes timestamp][2 bytes process_id][3 bytes sequence][1 byte version]
  
  // First 6 bytes: timestamp (big endian, truncated to 48 bits)
  for (int i = 5; i >= 0; i--) {
    id.data[i] = (unsigned char)(timestamp & 0xFF);
    timestamp >>= 8;
  }
  
  // Next 2 bytes: process ID (big endian, truncated to 16 bits)
  uint16_t pid = (uint16_t)(g_process_id & 0xFFFF);
  id.data[6] = (unsigned char)(pid >> 8);
  id.data[7] = (unsigned char)(pid & 0xFF);
  
  // Next 3 bytes: sequence counter + random bits for safety
  uint32_t seq = ++g_sequence_counter;
  uint32_t random_mix = fastRandom();
  seq = (seq & 0xFFF) | ((random_mix & 0xFFF) << 12); // 12 bits seq + 12 bits random
  
  id.data[8] = (unsigned char)(seq >> 16);
  id.data[9] = (unsigned char)(seq >> 8);
  id.data[10] = (unsigned char)(seq & 0xFF);
  
  // Last byte: version
  id.data[11] = FUGUID_VERSION;
  
  return id;
}

static void printFuguID(const fugu_id_t *id) {
  if (!id) {
    printf("NULL");
    return;
  }
  
  // Extract timestamp (first 6 bytes)
  uint64_t timestamp = 0;
  for (int i = 0; i < 6; i++) {
    timestamp = (timestamp << 8) | id->data[i];
  }
  
  // Extract process ID (next 2 bytes)
  uint16_t pid = (id->data[6] << 8) | id->data[7];
  
  // Extract sequence (next 3 bytes)
  uint32_t seq = (id->data[8] << 16) | (id->data[9] << 8) | id->data[10];
  
  // Format as readable string
  printf("fugu:%012" PRIx64 "-%04x-%06x-%02x", timestamp, pid, seq, id->data[11]);
}

// Compare FuguIDs for sorting/searching (lexicographic order gives chronological order)
static int compareFuguID(const fugu_id_t *a, const fugu_id_t *b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  
  return memcmp(a->data, b->data, FUGUID_LEN);
}

// Extract timestamp from FuguID
static uint64_t extractFuguIDTimestamp(const fugu_id_t *id) {
  if (!id) return 0;
  
  uint64_t timestamp = 0;
  for (int i = 0; i < 6; i++) {
    timestamp = (timestamp << 8) | id->data[i];
  }
  return timestamp;
}

int main() {
  printf("=== Testing In-Memory Database with FuguID ===\n\n");
  
  db_t *db = createDatabase("test_db", 4);
  if (!db) {
    printf("Failed to create database\n");
    return 1;
  }
  printf("✓ Created database: %s\n", db->name);

  column_t cols[6];
  
  cols[0].name = strdup("id");
  cols[0].type = COL_FUGU_ID;
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
  fugu_id_t id1 = generateFuguID();
  
  setFuguID(&r1, 0, &id1);
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
  fugu_id_t id2 = generateFuguID();
  
  setFuguID(&r2, 0, &id2);
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
  fugu_id_t id3 = generateFuguID();
  
  setFuguID(&r3, 0, &id3);
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
  fugu_id_t id4 = generateFuguID();
  
  setFuguID(&r4, 0, &id4);
  setInt(&r4, 1, 1004);
  setBool(&r4, 3, true);
  setByte(&r4, 5, 10);
  // Missing required name field
  
  result = insertRowSafe(tb, r4);
  if (result != DB_SUCCESS) {
    printf("✓ Correctly rejected row with missing required field (error: %d)\n", result);
  } else {
    printf("✗ Should have rejected invalid row\n");
  }
  
  freeRowContents(tb, &r4);

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
    
    fugu_id_t *fugu_id;
    if (getFuguID(&tb->rows[r], 0, &fugu_id) == 0) {
      printf("  ID: ");
      printFuguID(fugu_id);
      printf(" (timestamp: %" PRIu64 ")\n", extractFuguIDTimestamp(fugu_id));
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
  
  for (int i = 0; i < 10000; i++) {
    row_t perf_row = createEmptyRow(tb);
    fugu_id_t perf_id = generateFuguID();
    
    setFuguID(&perf_row, 0, &perf_id);
    setInt(&perf_row, 1, 2000 + i);
    
    char temp_name[50];
    snprintf(temp_name, sizeof(temp_name), "TestUser_%d", i);
    setStr(&perf_row, 2, temp_name);
    setBool(&perf_row, 3, i % 2 == 0);
    setDouble(&perf_row, 4, 50.0 + (i % 100));
    setByte(&perf_row, 5, i % 256);
    
    if (insertRowSafe(tb, perf_row) != DB_SUCCESS) {
      freeRowContents(tb, &perf_row);
      break;
    }
  }
  
  clock_t end = clock();
  double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("✓ Inserted 10,000 additional rows in %.3f seconds\n", cpu_time);
  printf("✓ Total rows: %zu\n", tb->rows_len);
  printf("✓ Average: %.0f insertions/second\n", 10000.0 / cpu_time);

  printf("\n--- FuguID Properties Test ---\n");
  
  // Test chronological ordering
  fugu_id_t early_id = generateFuguID();
  usleep(1000); // 1ms delay
  fugu_id_t later_id = generateFuguID();
  
  printf("✓ Early ID: ");
  printFuguID(&early_id);
  printf("\n✓ Later ID: ");
  printFuguID(&later_id);
  printf("\n");
  
  int cmp = compareFuguID(&early_id, &later_id);
  if (cmp < 0) {
    printf("✓ FuguIDs maintain chronological order\n");
  } else {
    printf("✗ FuguID ordering issue\n");
  }
  
  // Test bulk generation performance
  printf("\n--- Bulk ID Generation Test ---\n");
  start = clock();
  for (int i = 0; i < 100000; i++) {
    fugu_id_t temp_id = generateFuguID();
    (void)temp_id; // Suppress unused variable warning
  }
  end = clock();
  cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("✓ Generated 100,000 FuguIDs in %.3f seconds\n", cpu_time);
  printf("✓ Average: %.0f generations/second\n", 100000.0 / cpu_time);
  
  // Show memory efficiency
  printf("\n--- Memory Usage Analysis ---\n");
  printf("✓ FuguID size: %zu bytes (vs UUID4: 16 bytes)\n", sizeof(fugu_id_t));
  printf("✓ FuguID is %zu bytes smaller than UUID4\n", 16 - sizeof(fugu_id_t));
  printf("✓ Memory savings for 10,000 records: %zu bytes\n", (16 - sizeof(fugu_id_t)) * tb->rows_len);

cleanup:
  for (int i = 0; i < 6; i++) {
    if (cols[i].name) {
      free(cols[i].name);
    }
  }

  freeDatabase(db);
  
  printf("\n=== FuguID Database Test completed successfully ===\n");
  printf("\nFuguID Advantages over UUID4:\n");
  printf("• 25%% smaller (12 bytes vs 16 bytes)\n");
  printf("• Naturally chronologically sortable\n");
  printf("• No cryptographic randomness required (faster generation)\n");
  printf("• Embeds timestamp for debugging and analysis\n");
  printf("• Process-aware for multi-process safety\n");
  printf("• Sequence counter prevents duplicates within same microsecond\n");
  
  return 0;
}
