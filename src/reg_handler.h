#ifndef REG_HANDLER_H_
#define REG_HANDLER_H_
#include <regex.h>

typedef struct reg_result_s reg_result_t;
struct reg_result_s
{
	regex_t *reg;
	char result;
	ssize_t start;
	ssize_t end;
};

reg_result_t *reg_init(char * pattern);
void reg_handler(reg_result_t * reg_res, char *test_str);
void reg_destroy(reg_result_t * reg_res);

#endif
