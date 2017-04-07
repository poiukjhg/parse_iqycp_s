#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include "ips_types.h"
#include "mylogs.h"
#include "reg_handler.h"

reg_result_t *reg_init(char * pattern){
	char ebuf[128];
	reg_result_t * reg_res = (reg_result_t *)malloc(sizeof(reg_result_t));
	if (reg_res == NULL){
		handle_error("reg malloc\n\r");
	}
	memset(reg_res, 0, sizeof(reg_result_t));
	regex_t *reg = (regex_t *)malloc(sizeof(regex_t));
	reg_res->reg=reg;
	int err;
	err = regcomp(reg, pattern, REG_EXTENDED |REG_NEWLINE );
	if (err != 0){
		regerror(err, reg, ebuf, sizeof(ebuf));
		log_output("%s: pattern '%s' \n",ebuf, pattern);		
		return NULL;
	}
	return reg_res;
}

void reg_handler(reg_result_t * reg_res, char *test_str){
	int status;
	regex_t *reg = reg_res->reg; 
	regmatch_t pmatch[1];
	const size_t nmatch = 1;
	assert(reg_res);
	assert(reg);	
	//log_output("test str:%s\n\r", test_str);
	status = regexec(reg, test_str, nmatch, pmatch, 0);
	if (status == REG_NOMATCH){
		//log_output("no match\n\r");
		reg_res->result = REGEX_MISS;		
	}
	else if (status == 0) {
		log_output("test str:%s\n\r", test_str);
		log_output("match\n\r");
		reg_res->result = REGEX_HIT;
		reg_res->start = pmatch->rm_so;
		reg_res->end = pmatch->rm_eo;
	}		
}

void reg_destroy(reg_result_t * reg_res){
	regex_t *reg = reg_res->reg;
	regfree (reg);
	free(reg_res);
}

