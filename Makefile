# contrib/pg_credereum/Makefile

MODULE_big = pg_credereum
OBJS = pg_credereum.o ethereum.o
SHLIB_LINK = -lssl -lcrypto -lcurl -ljansson
PG_CPPFLAGS = -Wno-declaration-after-statement

EXTENSION = pg_credereum
DATA = pg_credereum--0.1.sql
PGFILEDESC = "pg_redereum extension make a PostgreSQL instance the part of Credereum platform"

ifndef PG_CONFIG
PG_CONFIG = pg_config
endif

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
