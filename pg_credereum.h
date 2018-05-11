/*-------------------------------------------------------------------------
 *
 * pg_credereum.h
 *		Headers of C-functions and hooks providing functionality of
 *		pg_credereum extension.
 *
 * Copyright (c) 2017-2018, Postgres Professional
 *
 * Author: Alexander Korotkov <a.korotkov@postgrespro.ru>
 *
 * IDENTIFICATION
 *	  contrib/pg_credereum/pg_credereum.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef _PG_CREDEREUM_H_
#define _PG_CREDEREUM_H_

#include "postgres.h"

extern char		   *ethRpcEndPoint;

extern void _PG_init(void);
extern void collector_main(Datum main_arg);

#endif /* _PG_CREDEREUM_H_ */