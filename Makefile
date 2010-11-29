all: clean
    gcc -Wall stuntd.c -o stuntd
    gcc -Wall -lpthread client.c -o client

clean:
    rm -fr stuntd client
