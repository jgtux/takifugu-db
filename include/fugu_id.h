#ifndef FUGU_ID_H
#define FUGU_ID_H

#include "db_types.h"

/* ID generation */
fugu_id_t generateFuguID(void);
void printFuguID(const fugu_id_t *id);
uint64_t extractFuguIDTimestamp(const fugu_id_t *id);
int compareFuguID(const fugu_id_t *a, const fugu_id_t *b);

/* ID column operations */
int setFuguID(table_t *tb, row_t *row, size_t idx, const fugu_id_t *val);
int getFuguID(const table_t *tb, const row_t *row, size_t idx, fugu_id_t **out,
              bool *is_null);

#endif /* FUGU_ID_H */
