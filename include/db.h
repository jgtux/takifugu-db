#ifndef DATABASE_H
#define DATABASE_H

#include "db_types.h"

/* Database lifecycle */
db_t *createDatabase(const char *name, size_t init_table_cap);
int deleteDatabase(db_t *db);

/* Table management */
int createTable(db_t *db, const char *name, column_t *columns, size_t col_len,
                size_t init_row_cap);
int deleteTable(db_t *db, size_t idx);
table_t *acquireTableRef(db_t *db, size_t idx);
void releaseTableRef(table_t *tb);

#endif /* DATABASE_H */
