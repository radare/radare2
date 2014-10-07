#ifndef STREAM_FILE_H
#define STREAM_FILE_H

#include <stdio.h>
#include "types.h"

///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
int init_r_stream_file(R_STREAM_FILE *stream_file, FILE *fp, int *pages,
							  int pages_amount, int size, int page_size);

// size by default = -1
///////////////////////////////////////////////////////////////////////////////
void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res);

///////////////////////////////////////////////////////////////////////////////
void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence);

///////////////////////////////////////////////////////////////////////////////
int stream_file_tell(R_STREAM_FILE *stream_file);

///////////////////////////////////////////////////////////////////////////////
void stream_file_get_data(R_STREAM_FILE *stream_file, char *data);

///////////////////////////////////////////////////////////////////////////////
void stream_file_get_size(R_STREAM_FILE *stream_file, int *data_size);

#endif // STREAM_FILE_H
