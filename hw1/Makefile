CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS = -shared -ldl -fPIC

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

libzpoline.so.1: libzpoline.1.o
	$(CC) $(LDFLAGS) -o $@ $< 

libzpoline.so.2: libzpoline.2.o
	$(CC) $(LDFLAGS) -o $@ $<

libzpoline.so: libzpoline.o
	$(CC) $(LDFLAGS) -o $@ $< -lopcodes -lbfd -lz -ldl

logger.so: logger.o
	$(CC) $(LDFLAGS) -o $@ $<

libzpoline.1.o: libzpoline.1.c
	$(CC) $(CFLAGS)  -c -o $@ $<

libzpoline.2.o: libzpoline.2.c
	$(CC) $(CFLAGS) -c -o $@ $<

libzpoline.o: libzpoline.c
	$(CC) $(CFLAGS) -DDIS_ASM_VER_239 -c -o $@ $<

logger.o: logger.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so main.c *html*

test1: libzpoline.so.1
	LD_PRELOAD=./libzpoline.so.1 ./ex1

test2: libzpoline.so.2
	LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
	LD_PRELOAD=./libzpoline.so.2 cat ex2-2.txt

test3: libzpoline.so
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3

test4: libzpoline.so logger.so
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts

test5: libzpoline.so logger.so
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1

test6: libzpoline.so logger.so
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'

.PHONY: all clean