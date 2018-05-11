#ifndef _PG_CREDEREUM_H_
#define _PG_CREDEREUM_H_

#include "postgres.h"

extern char		   *ethRpcEndPoint;

extern void _PG_init(void);
extern void collector_main(Datum main_arg);

#endif /* _PG_CREDEREUM_H_ */