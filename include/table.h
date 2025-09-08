#ifndef TABLE_H
#define TABLE_H

#include "db_types.h"

/* Row operations */
int createEmptyRow(table_t *tb, row_t *row);
int insertRow(db_t *db, size_t table_idx, row_t row);
int deleteRow(table_t *tb, size_t idx);

/* Column value setters */
int setInt(table_t *tb, row_t *row, size_t idx, const int *val);
int setInt64(table_t *tb, row_t *row, size_t idx, const int64_t *val);
int setUint(table_t *tb, row_t *row, size_t idx, const uint32_t *val);
int setUint64(table_t *tb, row_t *row, size_t idx, const uint64_t *val);
int setStr(table_t *tb, row_t *row, size_t idx, const char *str);
int setBool(table_t *tb, row_t *row, size_t idx, const bool *val);
int setDouble(table_t *tb, row_t *row, size_t idx, const double *val);
int setByte(table_t *tb, row_t *row, size_t idx, const unsigned char *val);

/* Column value getters */
int getInt(const table_t *tb, const row_t *row, size_t idx, int *out, bool *is_null);
int getInt64(const table_t *tb, const row_t *row, size_t idx, int64_t *out, bool *is_null);
int getUint(const table_t *tb, const row_t *row, size_t idx, uint32_t *out, bool *is_null);
int getUint64(const table_t *tb, const row_t *row, size_t idx, uint64_t *out, bool *is_null);
int getStr(const table_t *tb, const row_t *row, size_t idx, 
           char **out, size_t *out_len, bool *is_null);
int getBool(const table_t *tb, const row_t *row, size_t idx, bool *out, bool *is_null);
int getDouble(const table_t *tb, const row_t *row, size_t idx, double *out, bool *is_null);
int getByte(const table_t *tb, const row_t *row, size_t idx, unsigned char *out, bool *is_null);

#endif /* TABLE_H */
