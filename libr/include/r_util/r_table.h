#ifndef R_UTIL_TABLE_H
#define R_UTIL_TABLE_H

#include <r_util.h>

typedef struct {
	const char *name;
	RListComparator cmp;
} RTableColumnType;

extern RTableColumnType r_table_type_string;
extern RTableColumnType r_table_type_number;

typedef struct {
	char *name;
	RTableColumnType *type;
	int align; // left, right, center (TODO: unused)
	int width; // computed
	int maxWidth;
	bool forceUppercase;
} RTableColumn;

typedef struct {
	// TODO: use RVector
	RList *items;
} RTableRow;

typedef struct {
	RList *rows;
	RList *cols;
	int totalCols;
	bool showHeader;
	bool adjustedCols;
} RTable;

R_API void r_table_row_free(void *_row);
R_API void r_table_column_free(void *_col);
R_API RTable *r_table_new();
R_API void r_table_free(RTable *t);
R_API void r_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth);
R_API RTableRow *r_table_row_new(RList *items);
R_API void r_table_add_row(RTable *t, const char *name, ...);
R_API char *r_table_tofancystring(RTable *t);
R_API char *r_table_tostring(RTable *t);
R_API char *r_table_tocsv(RTable *t);
R_API char *r_table_tojson(RTable *t);
R_API void r_table_filter(RTable *t, int nth, int op, const char *un);
R_API void r_table_sort(RTable *t, int nth, bool inc);
R_API void r_table_query(RTable *t, const char *q);
R_API RTable *r_table_clone(RTable *t);
R_API RTable *r_table_push(RTable *t);
R_API RTable *r_table_pop(RTable *t);
R_API void r_table_fromjson(RTable *t, const char *csv);
R_API void r_table_fromcsv(RTable *t, const char *csv);
R_API char *r_table_tohtml(RTable *t);
R_API void r_table_transpose(RTable *t);
R_API void r_table_format(RTable *t, int nth, RTableColumnType *type);
R_API ut64 r_table_reduce(RTable *t, int nth);
R_API void r_table_columns(RTable *t, const char *name, ...);

#endif
