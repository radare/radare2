#ifndef R_JSON_H
#define R_JSON_H


#ifdef __cplusplus
extern "C" {
#endif

#define R_JSON_NULL       "null"
#define R_JSON_TRUE       "true"
#define R_JSON_FALSE      "false"
#define R_JSON_EMPTY_OBJ  "{}"
#define R_JSON_EMPTY_ARR  "[]"

typedef struct r_json_var RJSVar;

typedef struct r_json_string {
	const char* s;
	ut32 l;
} RJSString;

typedef struct r_json_array {
	RJSVar** a;
	ut32 l;
} RJSArray;

typedef struct r_json_object {
	RJSVar** a;
	const char** n;
	ut32 l;
} RJSObject;

struct r_json_var {
	int type;
	ut32 ref;
	union {
		int number;
		bool boolean;
		RJSArray array;
		RJSString string;
		RJSObject object;
	};
};

void r_json_var_free(RJSVar* var);
RJSVar* r_json_object_new();
RJSVar* r_json_array_new(int len);
RJSVar* r_json_string_new(const char* name);
RJSVar* r_json_number_new(int value);
RJSVar* r_json_boolean_new(bool value);
RJSVar* r_json_null_new();

void r_json_object_add(RJSVar* object, const char* name, RJSVar* value);
void r_json_array_add(RJSVar* array, RJSVar* value);
RJSVar* r_json_object_get(RJSVar* object, const char* name);
RJSVar* r_json_array_get(RJSVar* array, int index);

char* r_json_stringify(RJSVar* var, bool expanded);


#ifdef __cplusplus
}
#endif

#endif /* R_JSON_H */
