MODULES = ccnumber

EXTENSION = ccnumber
DATA = ccnumber--1.0.sql
PGFILEDESC = "ccnumber - encrypted CC number, with offloaded operations"

REGRESS = ccnumber

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

ccnumber-comparator:
	gcc ccnumber-comparator.c $(CFLAGS) -lpthread -lsodium -o ccnumber-comparator
