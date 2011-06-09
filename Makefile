all: clean
	gcc -Wall -lpthread stuntd.c -o stuntd
	gcc -Wall -lpthread raw_s.c -o raw_s

clean:
	rm -fr stuntd raw_s
