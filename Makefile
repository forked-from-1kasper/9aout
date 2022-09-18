all:
	gcc -static -Wl,-Ttext-segment,0x10000000 9aout.c -o 9aout

clean:
	rm -f 9aout