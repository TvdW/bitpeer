/*
 Copyright (c) 2013, Tom van der Woerdt
 */

#include <stdio.h>
#include "log.h"

/*
 Log levels:
 0: debug
 1: notice
 2: info
 3: warning
 4: error
 5: critical
 6: fatal
 */

void write_log(int level, const char *format, ...)
{
	if (level < 2) return;
	
	va_list arg;
	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);
	printf("\n");
}