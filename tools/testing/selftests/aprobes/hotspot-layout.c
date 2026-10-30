// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#include <jni.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct entry {
	const char *type, *field, *signature;
	int is_static;
	uint64_t offset;
	void *address;
};
static const struct {
	const char *type, *field, *define;
} fields[] = {
	{ "CodeBlob", "_size", "CB_SIZE" },
	{ "CodeBlob", "_code_offset", "CB_CODE" },
	{ "nmethod", "_method", "NM_METHOD" },
	{ "nmethod", "_verified_entry_offset", "NM_VERIFIED" },
	{ "nmethod", "_compile_id", "NM_COMPILE_ID" },
	{ "nmethod", "_comp_level", "NM_LEVEL" },
	{ "nmethod", "_osr_entry_point", "NM_OSR_ENTRY" },
	{ "Method", "_constMethod", "METHOD_CONST" },
	{ "ConstMethod", "_constants", "CONST_POOL" },
	{ "ConstMethod", "_name_index", "CONST_NAME_INDEX" },
	{ "ConstantPool", "_pool_holder", "CP_HOLDER" },
	{ "ConstantPool", "_length", "CP_LENGTH" },
	{ "Klass", "_name", "KLASS_NAME" },
	{ "Symbol", "_length", "SYMBOL_LENGTH" },
	{ "Symbol", "_body[0]", "SYMBOL_BODY" },
};
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
	(void)vm;
	(void)reserved;
	struct entry **table = dlsym(RTLD_DEFAULT, "gHotSpotVMStructs");
	uint64_t *stride =
		dlsym(RTLD_DEFAULT, "gHotSpotVMStructEntryArrayStride");
	void **types = dlsym(RTLD_DEFAULT, "gHotSpotVMTypes");
	uint64_t *type_stride =
		dlsym(RTLD_DEFAULT, "gHotSpotVMTypeEntryArrayStride");
	uint64_t *name_off =
		dlsym(RTLD_DEFAULT, "gHotSpotVMTypeEntryTypeNameOffset");
	uint64_t *size_off =
		dlsym(RTLD_DEFAULT, "gHotSpotVMTypeEntrySizeOffset");
	if (!options || !table || !stride || *stride != sizeof(struct entry) ||
	    !types || !type_stride || !name_off || !size_off)
		return JNI_ERR;
	FILE *out = fopen(options, "w");
	if (!out)
		return JNI_ERR;
	fputs("// SPDX-License-Identifier: GPL-2.0-only\n// Copyright 2026 Isovalent, Inc.\n",
	      out);
	for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		int found = 0;
		for (struct entry *p = *table; p->type; p++) {
			if (!p->is_static && !strcmp(p->type, fields[i].type) &&
			    !strcmp(p->field, fields[i].field)) {
				fprintf(out, "#define %s %llu\n",
					fields[i].define,
					(unsigned long long)p->offset);
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "missing VMStruct %s::%s\n",
				fields[i].type, fields[i].field);
			fclose(out);
			return JNI_ERR;
		}
	}
	int found = 0;
	for (char *p = *types;; p += *type_stride) {
		const char *name = *(const char **)(p + *name_off);
		if (!name)
			break;
		if (!strcmp(name, "ConstantPool")) {
			fprintf(out, "#define CP_SIZE %llu\n",
				(unsigned long long)*(uint64_t *)(p +
								  *size_off));
			found = 1;
			break;
		}
	}
	fclose(out);
	return found ? JNI_OK : JNI_ERR;
}
