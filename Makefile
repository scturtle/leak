all: leak.so
leak.so: leak.cc
	g++ -std=c++14 -Wall -shared -fPIC -O2 -g $< -o $@ -pthread -ldl
clean:
	rm leak.so
.PHONY: clean
