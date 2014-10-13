#ifndef TPI_H
#define TPI_H

#include "types.h"

///////////////////////////////////////////////////////////////////////////////
void init_tpi_stream(STpiStream *tpi_stream);

///////////////////////////////////////////////////////////////////////////////
void parse_tpi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream);

// TODO: Remove to separate file
void parse_sctring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len);

///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name);
#endif // TPI_H
