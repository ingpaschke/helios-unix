#ifndef HELIOS_UNIX_GLOB_H
#define HELIOS_UNIX_GLOB_H
#include <stddef.h>
typedef struct {size_t gl_pathc;char **gl_pathv;size_t gl_offs;int gl_flags;} glob_t;
#define GLOB_ERR 1
#define GLOB_MARK 2
#define GLOB_NOSORT 4
#define GLOB_DOOFFS 8
#define GLOB_NOCHECK 16
#define GLOB_APPEND 32
#define GLOB_NOESCAPE 64
#define GLOB_TILDE 128
#define GLOB_NOSPACE 1
#define GLOB_ABORTED 2
#define GLOB_NOMATCH 3
int glob(const char *,int,int (*)(const char *,int),glob_t *);
void globfree(glob_t *);
#endif
