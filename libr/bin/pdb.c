#include <r_pdb.h>
//#include <tpi.c>
#include <string.h>

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
#define PDB7_SIGNATURE_LEN 32
#define PDB2_SIGNATURE_LEN 51

typedef struct {
	int stream_size;
	char *stream_pages;
} SPage;

typedef struct {
	FILE *fp;
	int *pages;
	int page_size;
	int pages_amount;
	int end;
	int pos;
} R_STREAM_FILE;

typedef struct {
	FILE *fp;
	int *pages;
	int pages_amount;
	int indx;
	int page_size;
	int size;
	R_STREAM_FILE stream_file;
	// int fast_load;
	// ... parent;
} R_PDB_STREAM;

typedef struct {
	R_PDB_STREAM pdb_stream;
	int num_streams;
	RList *streams_list;
} R_PDB7_ROOT_STREAM;

typedef enum {
	ePDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	ePDB_STREAM_PDB, // PDB STREAM INFO
	ePDB_STREAM_TPI, // TYPE INFO
	ePDB_STREAM_DBI, // DEBUG INFO
	ePDB_STREAM_MAX
} EStream;

typedef void (*f_load)(void *parsed_pdb_stream, R_STREAM_FILE *stream);

typedef struct {
	R_PDB_STREAM *pdb_stream;
	f_load load;
} SParsedPDBStream;

//### Header structures
//def OffCb(name):
//    return Struct(name,
//        SLInt32("off"),
//        SLInt32("cb"),
//    )

//TPI = Struct("TPIHash",
//    ULInt16("sn"),
//    Padding(2),
//    SLInt32("HashKey"),
//    SLInt32("Buckets"),
//    OffCb("HashVals"),
//    OffCb("TiOff"),
//    OffCb("HashAdj"),
//)

typedef struct {
	int off;
	int cb;
} SOffCb;

typedef struct {
	short sn;
	short padding;
	int hash_key;
	int buckets;
	SOffCb hash_vals;
	SOffCb ti_off;
	SOffCb hash_adj;
} STPI;

typedef struct {
	unsigned int version;
	int hdr_size;
	unsigned int ti_min;
	unsigned int ti_max;
	unsigned int follow_size;
	STPI tpi;
} STPIHeader;

//# Fewer than 255 values so we're ok here
//leaf_type = Enum(ULInt16("leaf_type"),
//    LF_MODIFIER_16t         = 0x00000001,
//    LF_POINTER_16t          = 0x00000002,
//    LF_ARRAY_16t            = 0x00000003,
//    LF_CLASS_16t            = 0x00000004,
//    LF_STRUCTURE_16t        = 0x00000005,
//    LF_UNION_16t            = 0x00000006,
//    LF_ENUM_16t             = 0x00000007,
//    LF_PROCEDURE_16t        = 0x00000008,
//    LF_MFUNCTION_16t        = 0x00000009,
//    LF_VTSHAPE              = 0x0000000A,
//    LF_COBOL0_16t           = 0x0000000B,
//    LF_COBOL1               = 0x0000000C,
//    LF_BARRAY_16t           = 0x0000000D,
//    LF_LABEL                = 0x0000000E,
//    LF_NULL                 = 0x0000000F,
//    LF_NOTTRAN              = 0x00000010,
//    LF_DIMARRAY_16t         = 0x00000011,
//    LF_VFTPATH_16t          = 0x00000012,
//    LF_PRECOMP_16t          = 0x00000013,
//    LF_ENDPRECOMP           = 0x00000014,
//    LF_OEM_16t              = 0x00000015,
//    LF_TYPESERVER_ST        = 0x00000016,
//    LF_SKIP_16t             = 0x00000200,
//    LF_ARGLIST_16t          = 0x00000201,
//    LF_DEFARG_16t           = 0x00000202,
//    LF_LIST                 = 0x00000203,
//    LF_FIELDLIST_16t        = 0x00000204,
//    LF_DERIVED_16t          = 0x00000205,
//    LF_BITFIELD_16t         = 0x00000206,
//    LF_METHODLIST_16t       = 0x00000207,
//    LF_DIMCONU_16t          = 0x00000208,
//    LF_DIMCONLU_16t         = 0x00000209,
//    LF_DIMVARU_16t          = 0x0000020A,
//    LF_DIMVARLU_16t         = 0x0000020B,
//    LF_REFSYM               = 0x0000020C,
//    LF_BCLASS_16t           = 0x00000400,
//    LF_VBCLASS_16t          = 0x00000401,
//    LF_IVBCLASS_16t         = 0x00000402,
//    LF_ENUMERATE_ST         = 0x00000403,
//    LF_FRIENDFCN_16t        = 0x00000404,
//    LF_INDEX_16t            = 0x00000405,
//    LF_MEMBER_16t           = 0x00000406,
//    LF_STMEMBER_16t         = 0x00000407,
//    LF_METHOD_16t           = 0x00000408,
//    LF_NESTTYPE_16t         = 0x00000409,
//    LF_VFUNCTAB_16t         = 0x0000040A,
//    LF_FRIENDCLS_16t        = 0x0000040B,
//    LF_ONEMETHOD_16t        = 0x0000040C,
//    LF_VFUNCOFF_16t         = 0x0000040D,
//    LF_TI16_MAX             = 0x00001000,
//    LF_MODIFIER             = 0x00001001,
//    LF_POINTER              = 0x00001002,
//    LF_ARRAY_ST             = 0x00001003,
//    LF_CLASS_ST             = 0x00001004,
//    LF_STRUCTURE_ST         = 0x00001005,
//    LF_UNION_ST             = 0x00001006,
//    LF_ENUM_ST              = 0x00001007,
//    LF_PROCEDURE            = 0x00001008,
//    LF_MFUNCTION            = 0x00001009,
//    LF_COBOL0               = 0x0000100A,
//    LF_BARRAY               = 0x0000100B,
//    LF_DIMARRAY_ST          = 0x0000100C,
//    LF_VFTPATH              = 0x0000100D,
//    LF_PRECOMP_ST           = 0x0000100E,
//    LF_OEM                  = 0x0000100F,
//    LF_ALIAS_ST             = 0x00001010,
//    LF_OEM2                 = 0x00001011,
//    LF_SKIP                 = 0x00001200,
//    LF_ARGLIST              = 0x00001201,
//    LF_DEFARG_ST            = 0x00001202,
//    LF_FIELDLIST            = 0x00001203,
//    LF_DERIVED              = 0x00001204,
//    LF_BITFIELD             = 0x00001205,
//    LF_METHODLIST           = 0x00001206,
//    LF_DIMCONU              = 0x00001207,
//    LF_DIMCONLU             = 0x00001208,
//    LF_DIMVARU              = 0x00001209,
//    LF_DIMVARLU             = 0x0000120A,
//    LF_BCLASS               = 0x00001400,
//    LF_VBCLASS              = 0x00001401,
//    LF_IVBCLASS             = 0x00001402,
//    LF_FRIENDFCN_ST         = 0x00001403,
//    LF_INDEX                = 0x00001404,
//    LF_MEMBER_ST            = 0x00001405,
//    LF_STMEMBER_ST          = 0x00001406,
//    LF_METHOD_ST            = 0x00001407,
//    LF_NESTTYPE_ST          = 0x00001408,
//    LF_VFUNCTAB             = 0x00001409,
//    LF_FRIENDCLS            = 0x0000140A,
//    LF_ONEMETHOD_ST         = 0x0000140B,
//    LF_VFUNCOFF             = 0x0000140C,
//    LF_NESTTYPEEX_ST        = 0x0000140D,
//    LF_MEMBERMODIFY_ST      = 0x0000140E,
//    LF_MANAGED_ST           = 0x0000140F,
//    LF_ST_MAX               = 0x00001500,
//    LF_TYPESERVER           = 0x00001501,
//    LF_ENUMERATE            = 0x00001502,
//    LF_ARRAY                = 0x00001503,
//    LF_CLASS                = 0x00001504,
//    LF_STRUCTURE            = 0x00001505,
//    LF_UNION                = 0x00001506,
//    LF_ENUM                 = 0x00001507,
//    LF_DIMARRAY             = 0x00001508,
//    LF_PRECOMP              = 0x00001509,
//    LF_ALIAS                = 0x0000150A,
//    LF_DEFARG               = 0x0000150B,
//    LF_FRIENDFCN            = 0x0000150C,
//    LF_MEMBER               = 0x0000150D,
//    LF_STMEMBER             = 0x0000150E,
//    LF_METHOD               = 0x0000150F,
//    LF_NESTTYPE             = 0x00001510,
//    LF_ONEMETHOD            = 0x00001511,
//    LF_NESTTYPEEX           = 0x00001512,
//    LF_MEMBERMODIFY         = 0x00001513,
//    LF_MANAGED              = 0x00001514,
//    LF_TYPESERVER2          = 0x00001515,
//    LF_CHAR                 = 0x00008000,
//    LF_SHORT                = 0x00008001,
//    LF_USHORT               = 0x00008002,
//    LF_LONG                 = 0x00008003,
//    LF_ULONG                = 0x00008004,
//    LF_REAL32               = 0x00008005,
//    LF_REAL64               = 0x00008006,
//    LF_REAL80               = 0x00008007,
//    LF_REAL128              = 0x00008008,
//    LF_QUADWORD             = 0x00008009,
//    LF_UQUADWORD            = 0x0000800A,
//    LF_REAL48               = 0x0000800B,
//    LF_COMPLEX32            = 0x0000800C,
//    LF_COMPLEX64            = 0x0000800D,
//    LF_COMPLEX80            = 0x0000800E,
//    LF_COMPLEX128           = 0x0000800F,
//    LF_VARSTRING            = 0x00008010,
//    LF_OCTWORD              = 0x00008017,
//    LF_UOCTWORD             = 0x00008018,
//    LF_DECIMAL              = 0x00008019,
//    LF_DATE                 = 0x0000801A,
//    LF_UTF8STRING           = 0x0000801B,
//    LF_PAD0                 = 0x000000F0,
//    LF_PAD1                 = 0x000000F1,
//    LF_PAD2                 = 0x000000F2,
//    LF_PAD3                 = 0x000000F3,
//    LF_PAD4                 = 0x000000F4,
//    LF_PAD5                 = 0x000000F5,
//    LF_PAD6                 = 0x000000F6,
//    LF_PAD7                 = 0x000000F7,
//    LF_PAD8                 = 0x000000F8,
//    LF_PAD9                 = 0x000000F9,
//    LF_PAD10                = 0x000000FA,
//    LF_PAD11                = 0x000000FB,
//    LF_PAD12                = 0x000000FC,
//    LF_PAD13                = 0x000000FD,
//    LF_PAD14                = 0x000000FE,
//    LF_PAD15                = 0x000000FF
//)

//Type = Debugger(Struct("type",
//    leaf_type,
//    Switch("type_info", lambda ctx: ctx.leaf_type,
//        {
//            "LF_ARGLIST": lfArgList,
//            "LF_ARRAY": lfArray,
//            "LF_ARRAY_ST": lfArrayST,
//            "LF_BITFIELD": lfBitfield,
//            "LF_CLASS": lfClass,
//            "LF_ENUM": lfEnum,
//            "LF_FIELDLIST": lfFieldList,
//            "LF_MFUNCTION": lfMFunc,
//            "LF_MODIFIER": lfModifier,
//            "LF_POINTER": lfPointer,
//            "LF_PROCEDURE": lfProcedure,
//            "LF_STRUCTURE": lfStructure,
//            "LF_STRUCTURE_ST": lfStructureST,
//            "LF_UNION": lfUnion,
//            "LF_UNION_ST": lfUnionST,
//            "LF_VTSHAPE": lfVTShape,
//        },
//        default = Pass,
//    ),
//))

typedef struct {
	unsigned short length;
	// Type type_data
//	Tunnel(
//        String("type_data", lambda ctx: ctx.length),
//        Type,
//    ),
} STypes;

//TPIStream = Struct("TPIStream",
//    Header,
//    Array(lambda ctx: ctx.TPIHeader.ti_max - ctx.TPIHeader.ti_min, Types),
//)
typedef struct {
	STPIHeader header;

} STpiStream;

typedef struct {
	unsigned int data1;
	unsigned short data2;
	unsigned short data3;
	char data4[8];
} SGUID;

typedef struct {
	unsigned int version;
	unsigned int time_date_stamp;
	unsigned int age;
	SGUID guid;
	unsigned int cb_names;
	char *names;
} SPDBInfoStreamD;

typedef struct {
	SParsedPDBStream *parsed_pdb_stream;
	SPDBInfoStreamD data;
} SPDBInfoStream;



///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
static int init_r_stream_file(R_STREAM_FILE *stream_file, FILE *fp, int *pages,
							  int pages_amount, int size, int page_size)
{
	stream_file->fp = fp;
	stream_file->pages = pages;
	stream_file->pages_amount = pages_amount;
	stream_file->page_size = page_size;

	if (size == -1) {
			stream_file->end = pages_amount * page_size;
	} else {
			stream_file->end = size;
	}

	stream_file->pos = 0;

	return 1;
}

#define GET_PAGE(pn, off, pos, page_size)	{ \
	(pn) = (pos) / (page_size); \
	(off) = (pos) % (page_size); \
}

///////////////////////////////////////////////////////////////////////////////
static void stream_file_read_pages(R_STREAM_FILE *stream_file, int start_indx,
								   int end_indx, char *res)
{
	int i;
	int page_offset;
	int curr_pos;
//	char buffer[1024];

	for (i = start_indx; i < end_indx; i++) {
		page_offset = stream_file->pages[i] * stream_file->page_size;
		fseek(stream_file->fp, page_offset, SEEK_SET);
//		curr_pos = ftell(stream_file->fp);
		fread(res, stream_file->page_size, 1, stream_file->fp);
		res += stream_file->page_size;
	}
}

#define READ_PAGES(start_indx, end_indx) { \
	for (i = start_indx; i < end_indx; i++) { \
		fseek(stream_file->fp, stream_file->pages[i] * stream_file->page_size, SEEK_SET); \
		fread(tmp, stream_file->page_size, 1, stream_file->fp); \
		tmp += stream_file->page_size; \
	} \
}

// size by default = -1
///////////////////////////////////////////////////////////////////////////////
static unsigned char* stream_file_read(R_STREAM_FILE *stream_file, int size)
{
	int pn_start, off_start, pn_end, off_end;
	int i = 0;
	char *pdata = 0;
	char *tmp;
	char *ret = 0;
	int len = 0;

	if (size == -1) {
		pdata = (char *) malloc(stream_file->pages_amount * stream_file->page_size);
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		tmp = pdata;
		READ_PAGES(0, stream_file->pages_amount)
		stream_file->pos = stream_file->end;
		tmp = pdata;
		ret = (char *) malloc(stream_file->end - off_start);
		memcpy(ret, tmp + off_start, stream_file->end - off_start);
		free(pdata);
	} else {
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		GET_PAGE(pn_end, off_end, stream_file->pos + size, stream_file->page_size);

		pdata = (char *) malloc(stream_file->page_size * (pn_end + 1 - pn_start));
		tmp = pdata;
		stream_file_read_pages(stream_file, pn_start, pn_end + 1, tmp);
		//READ_PAGES(pn_start, (pn_end + 1))
		stream_file->pos += size;
		ret = (char *) malloc((stream_file->page_size - off_end));
		tmp = pdata;
		memcpy(ret, tmp + off_start, (stream_file->page_size - off_end) - off_start);
		free(pdata);
	}

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
//def seek(self, offset, whence=0):
//    if whence == 0:
//        self.pos = offset
//    elif whence == 1:
//        self.pos += offset
//    elif whence == 2:
//        self.pos = self.end + offset
//if self.pos < 0: self.pos = 0
//if self.pos > self.end: self.pos = self.end
// whence by default = 0
static void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence)
{
	switch (whence) {
	case 0:
		stream_file->pos = offset;
		break;
	case 1:
		stream_file->pos += offset;
		break;
	case 2:
		stream_file->pos = stream_file->end + offset;
		break;
	default:
		break;
	}

	if (stream_file->pos < 0) stream_file->pos = 0;
	if (stream_file->pos > stream_file->end) stream_file->pos = stream_file->end;
}

///////////////////////////////////////////////////////////////////////////////
static int stream_file_tell(R_STREAM_FILE *stream_file)
{
	return stream_file->pos;
}

//def _get_data(self):
//    pos = self.stream_file.tell()
//    self.stream_file.seek(0)
//    data = self.stream_file.read()
//    self.stream_file.seek(pos)
//    return data
static char* pdb_stream_get_data(R_PDB_STREAM *pdb_stream)
{
	char *data;
	int pos = stream_file_tell(&pdb_stream->stream_file);
	stream_file_seek(&pdb_stream->stream_file, 0, 0);
	data = stream_file_read(&pdb_stream->stream_file, -1);
	stream_file_seek(&pdb_stream->stream_file, pos, 0);
	return data;
}

///////////////////////////////////////////////////////////////////////////////
/// size - default value = -1
/// page_size - default value = 0x1000
///////////////////////////////////////////////////////////////////////////////
static int init_r_pdb_stream(R_PDB_STREAM *pdb_stream, FILE *fp, int *pages,
							 int pages_amount, int index, int size, int page_size)
{
	printf("init_r_pdb_stream()\n");

	pdb_stream->fp = fp;
	pdb_stream->pages = pages;
	pdb_stream->indx = index;
	pdb_stream->page_size = page_size;
	pdb_stream->pages_amount = pages_amount;

	if (size == -1) {
		pdb_stream->size =  pages_amount * page_size;
	} else {
		pdb_stream->size = size;
	}

	init_r_stream_file(&(pdb_stream->stream_file), fp, pages, pages_amount, size, page_size);

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int read_int_var(char *var_name, int *var, FILE *fp)
{
	int bytes_read = fread(var, 4, 1, fp);
	if (bytes_read != 1) {
		printf("error while reading from file [%s]", var_name);
		return 0;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int count_pages(int length, int page_size)
{
	int num_pages = 0;
	num_pages = length / page_size;
	if (length % page_size)
		num_pages++;
	return num_pages;
}

static int init_pdb7_root_stream(R_PDB *pdb, int *root_page_list, int pages_amount,
								 EStream indx, int root_size, int page_size)
{
	int num_streams = 0;
	char *data = 0;
	char *tmp_data = 0;
	int *tmp_sizes = 0;
	int num_pages = 0;
	int i = 0;
	int *sizes = 0;
	int stream_size = 0;
	int pos = 0;

	char *tmp;
	int some_int;

	R_PDB7_ROOT_STREAM *root_stream7;

	pdb->root_stream = (R_PDB7_ROOT_STREAM *)malloc(sizeof(R_PDB7_ROOT_STREAM));
	init_r_pdb_stream(pdb->root_stream, pdb->fp, root_page_list, pages_amount,
					  indx, root_size, page_size);

	root_stream7 = pdb->root_stream;
	// FIXME: data need to be free somewhere!!!
	data = pdb_stream_get_data(&(root_stream7->pdb_stream));

	num_streams = *(int *)data;
	tmp_data = data;
	tmp_data += 4;

	root_stream7->num_streams = num_streams;

	// FIXME: size need to be free somewhere!!!
	sizes = (int *) malloc(num_streams * 4);

	for (i = 0; i < num_streams; i++) {
		stream_size = *(int *)(tmp_data);
		tmp_data += 4;
		if (stream_size == 0xffffffff) {
			stream_size = 0;
		}
		memcpy(sizes + i, &stream_size, 4);
	}

	tmp_data = ((char *)data + num_streams * 4 + 4);
	//FIXME: free list...
	root_stream7->streams_list = r_list_new();
	RList *pList = root_stream7->streams_list;
	SPage *page = 0;
	for (i = 0; i < num_streams; i++) {
		num_pages = count_pages(sizes[i], page_size);

		// FIXME: remove tmp..
		tmp = (char *) malloc(num_pages * 4);
		memset(tmp, 0, num_pages * 4);
		page = (SPage *) malloc(sizeof(SPage));
		if (num_pages != 0) {
			memcpy(tmp, tmp_data + pos, num_pages * 4);
			pos += num_pages * 4;

			page->stream_size = sizes[i];
			page->stream_pages = tmp;
		} else {
			page->stream_size = 0;
			page->stream_pages = 0;
			free(tmp);
		}

		r_list_append(pList, page);
	}

	printf("init_pdb7_root_stream()\n");
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static void init_parsed_pdb_stream(SParsedPDBStream *pdb_stream, FILE *fp, int *pages,
								   int pages_amount, int index, int size,
								   int page_size, f_load pLoad)
{
	// FIXME: free memory...
	pdb_stream->pdb_stream = (R_PDB_STREAM *) malloc(sizeof(R_PDB_STREAM));
	init_r_pdb_stream(pdb_stream->pdb_stream, fp, pages, pages_amount, index, size, page_size);
	pdb_stream->load = pLoad;
	if (pLoad != NULL) {
		pLoad(pdb_stream, &(pdb_stream->pdb_stream->stream_file));
	}
}

static void parse_pdb_info_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream)
{
	SPDBInfoStream *tmp = (SPDBInfoStream *)parsed_pdb_stream;
	tmp->data.version = *(int *)stream_file_read(stream, 4);
	tmp->data.time_date_stamp = *(int *)stream_file_read(stream, 4);
	tmp->data.age = *(int *)stream_file_read(stream, 4);
	tmp->data.guid.data1 = *(int *)stream_file_read(stream, 4);
	tmp->data.guid.data2 = *(short *)stream_file_read(stream, 2);
	tmp->data.guid.data3 = *(short *)stream_file_read(stream, 2);
	memcpy(tmp->data.guid.data4, stream_file_read(stream, 8), 8);
	tmp->data.cb_names = *(int *)stream_file_read(stream, 4);
	//FIXME: free memory
	tmp->data.names = (char *) malloc(tmp->data.cb_names);
	memcpy(tmp->data.names, stream_file_read(stream, tmp->data.cb_names), tmp->data.cb_names);
}

static void parse_tpi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream)
{
	STPIHeader tpi_header = *(STPIHeader *)stream_file_read(stream, sizeof(STPIHeader));
	STypes types;
	unsigned char *leaf_type;
	unsigned short leaf_type_short;
	types.length = *(unsigned short *)stream_file_read(stream, sizeof(unsigned short));
	leaf_type = stream_file_read(stream, types.length);
	leaf_type_short = *(unsigned short *)leaf_type;

//	tpi_header.version = *(unsigned int *)stream_file_read(stream, 4);
//	tpi_header.hdr_size = *(int *)stream_file_read(stream, 4);
//	tpi_header.ti_min = *(unsigned int *)stream_file_read(stream, 4);
//	tpi_header.ti_max = *(unsigned int *)stream_file_read(stream, 4);
//	tpi_header.follow_size = *(unsigned int *)stream_file_read(stream, 4);
}

//self.streams = []
//for i in range(len(rs.streams)):
//    try:
//        pdb_cls = self._stream_map[i]
//    except KeyError:
//        pdb_cls = PDBStream
//    stream_size, stream_pages = rs.streams[i]
//    self.streams.append(
//        pdb_cls(self.fp, stream_pages, i, size=stream_size,
//            page_size=self.page_size, fast_load=self.fast_load,
//            parent=self))

//# Sets up access to streams by name
//self._update_names()

//# Second stage init. Currently only used for FPO strings
//if not self.fast_load:
//    for s in self.streams:
//        if hasattr(s, 'load2'):
//            s.load2()
///////////////////////////////////////////////////////////////////////////////
static int pdb_read_root(R_PDB *pdb)
{
	int i = 0;

	RList *pList = pdb->pdb_streams;
	R_PDB7_ROOT_STREAM *root_stream = pdb->root_stream;
	R_PDB_STREAM *pdb_stream = 0;
	SParsedPDBStream *parsed_pdb_stream = 0;
	RListIter *it;
	SPage *page = 0;

	it = r_list_iterator(root_stream->streams_list);
	while (r_list_iter_next(it)) {
		page = (SPage*) r_list_iter_get(it);
		switch (i) {
		case 1:
			//TODO: free memory
			parsed_pdb_stream = (SParsedPDBStream *) malloc(sizeof(SParsedPDBStream));
			init_parsed_pdb_stream(parsed_pdb_stream, pdb->fp, page->stream_pages,
								   root_stream->pdb_stream.pages_amount, i,
								   page->stream_size,
								   root_stream->pdb_stream.page_size, &parse_pdb_info_stream);
			r_list_append(pList, parsed_pdb_stream);
			break;
		case 2:
			//TODO: free memory
			parsed_pdb_stream = (SParsedPDBStream *) malloc(sizeof(SParsedPDBStream));
			init_parsed_pdb_stream(parsed_pdb_stream, pdb->fp, page->stream_pages,
								   root_stream->pdb_stream.pages_amount, i,
								   page->stream_size,
								   root_stream->pdb_stream.page_size, &parse_tpi_stream);
			r_list_append(pList, parsed_pdb_stream);
			break;
		case 3:
			//TODO: free memory
			parsed_pdb_stream = (SParsedPDBStream *) malloc(sizeof(SParsedPDBStream));
			init_parsed_pdb_stream(parsed_pdb_stream, pdb->fp, page->stream_pages,
								   root_stream->pdb_stream.pages_amount, i,
								   page->stream_size,
								   root_stream->pdb_stream.page_size, 0);
			r_list_append(pList, parsed_pdb_stream);
			break;
		default:
			pdb_stream = (R_PDB_STREAM *)malloc(sizeof(R_PDB_STREAM));
			init_r_pdb_stream(pdb_stream, pdb->fp, page->stream_pages,
							  root_stream->pdb_stream.pages_amount, i,
							  page->stream_size,
							  root_stream->pdb_stream.page_size);
			r_list_append(pList, pdb_stream);
			break;
		}
		i++;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int pdb7_parse(R_PDB *pdb)
{
	printf("pdb7_parse()\n");

	char signature[PDB7_SIGNATURE_LEN + 1];
	int page_size = 0;
	int alloc_tbl_ptr = 0;
	int num_file_pages = 0;
	int root_size = 0;
	int reserved = 0;

	int num_root_pages = 0;
	int num_root_index_pages = 0;
	int *root_index_pages = 0;
	void *root_page_data = 0;
	int *root_page_list = 0;

	int i = 0;
	void *p_tmp;

	int bytes_read = 0;

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("error while reading PDB7_SIGNATURE\n");
		goto error;
	}

	if (read_int_var("page_size", &page_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("alloc_tbl_ptr", &alloc_tbl_ptr, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("num_file_pages", &num_file_pages, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("root_size", &root_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("reserved", &reserved, pdb->fp) == 0) {
		goto error;
	}

	// FIXME: why they is not equal ????
	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN) != 0) {
		printf("Invalid signature for PDB7 format\n");
		//goto error;
	}

	// TODO:
	// create stream of maps and names
	// ...

	num_root_pages = count_pages(root_size, page_size);
	num_root_index_pages = count_pages((num_root_pages * 4), page_size);

	root_index_pages = (int *)malloc(sizeof(int) * num_root_index_pages);
	if (!root_index_pages) {
		printf("error memory allocation\n");
		goto error;
	}

	bytes_read = fread(root_index_pages, 4, num_root_index_pages, pdb->fp);
	if (bytes_read != num_root_index_pages) {
		printf("error while reading root_index_pages\n");
		goto error;
	}

	root_page_data = (int *)malloc(page_size * num_root_index_pages);
	if (!root_page_data) {
		printf("error memory allocation of root_page_data\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_index_pages; i++) {
		fseek(pdb->fp, root_index_pages[i] * page_size, SEEK_SET);
		fread(p_tmp, page_size, 1, pdb->fp);
		p_tmp = (char *)p_tmp + page_size;
	}

	root_page_list = (int *)malloc(sizeof(int) * num_root_pages);
	if (!root_page_list) {
		printf("error: memory allocation of root page\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_pages; i++) {
		root_page_list[i] = *((int *)p_tmp);
		p_tmp = (int *)p_tmp + 1;
	}

	init_pdb7_root_stream(pdb, root_page_list, num_root_pages, ePDB_STREAM_ROOT, root_size, page_size);
	pdb_read_root(pdb);

	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 1;

error:
	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static void finish_pdb_parse(R_PDB *pdb)
{
	fclose(pdb->fp);
	printf("finish_pdb_parse()\n");
}

///////////////////////////////////////////////////////////////////////////////
int init_pdb_parser(R_PDB *pdb)
{
	char *signature = 0;
	int bytes_read = 0;

	if (!pdb) {
		printf("struct R_PDB is not correct\n");
		goto error;
	}

	pdb->fp = fopen(pdb->file_name, "rb");
	if (!pdb->fp) {
		printf("file %s can not be open\n", pdb->file_name);
		goto error;
	}

	signature = (char *)malloc(sizeof(char) * PDB7_SIGNATURE_LEN);
	if (!signature) {
		printf("memory allocation error\n");
		goto error;
	}

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("file reading error\n");
		goto error;
	}

	fseek(pdb->fp, 0, SEEK_SET);

	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN)) {
		pdb->pdb_parse =pdb7_parse;
	} else {
		printf("unsupported pdb format\n");
		goto error;
	}

	if (signature) {
		free(signature);
		signature = 0;
	}

	//FIXME: remove pdb_streams_list
	pdb->pdb_streams = r_list_new();
	pdb->stream_map = 0;
	pdb->finish_pdb_parse = finish_pdb_parse;
	printf("init_pdb_parser() finish with success\n");
	return 1;

error:
	if (signature) {
		free(signature);
		signature = 0;
	}

	return 0;
}
