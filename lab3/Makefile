.PHONY: all test clean

CXX = gcc
PX = python

all: libsolver.so gotoku libgotoku.so

libgotoku.so: libgotoku_dummy.c
	$(CXX) -o $@ -shared -fPIC $^ -ldl

libsolver.so: libsolver.c got_offsets.h
	$(CXX) -o $@ -shared -fPIC $^ -ldl

got_offsets.h: got.py gotoku
	$(PX) got.py

gotoku.local: gotoku.c libgotoku.so
	$(CXX) -o $@ -Wall -g $< -L./ -Wl,-rpath,./ -lgotoku

test:
	LD_PRELOAD=./libsolver.so ./gotoku

clean:
	rm -f *.so *.o gotoku.local got_offsets.h
