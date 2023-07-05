CFILES  = errstr.c 9aout.c
BINNAME = 9aout
CFLAGS  = -static -fomit-frame-pointer -Wl,-Ttext-segment,0x10000000

all: debug

release:
	gcc $(CFLAGS) $(CFILES) -o $(BINNAME)

debug:
	gcc -DDEBUG -g $(CFLAGS) $(CFILES) -o $(BINNAME)

clean:
	rm -f 9aout

install-binfmt: release
	sudo ./scripts/install-binfmt.sh

uninstall-binfmt:
	sudo ./scripts/uninstall-binfmt.sh