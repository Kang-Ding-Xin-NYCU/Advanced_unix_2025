CC = gcc

.PHONY: all clean

all: sdb

sdb: sdb.c
	$(CC) $^ -o $@ -lcapstone

clean:
	rm -rf sdb