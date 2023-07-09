CC         = gcc
SOURCEDIR  = source
INCLUDEDIR = include
BINNAME    = 9aout
LDFLAGS    = -static -Wl,-Ttext-segment,0x10000000
CFLAGS     = -Wall -Wno-misleading-indentation -fomit-frame-pointer -I$(INCLUDEDIR)

CFILES := $(shell find $(SOURCEDIR) -name '*.c' | sort -n)
DFILES := $(CFILES:%.c=%.d)
OFILES := $(foreach filepath,$(CFILES),$(notdir $(filepath:%.c=%.o)))

ifdef DEBUG
	CFLAGS += -g -DDEBUG
endif

all: $(BINNAME)

$(BINNAME): $(OFILES)
	$(CC) $(LDFLAGS) $(OFILES) -o $(BINNAME)

%.d: %.c
	$(CC) -I$(INCLUDEDIR) -MM $< > $@
	echo "\\t$(CC) $(CFLAGS) -c $< -o $(notdir $(<:%.c=%.o))" >> $@

clean:
	rm -f $(BINNAME) $(OFILES) $(DFILES)

install-binfmt: $(BINNAME)
	./scripts/install-binfmt.sh

uninstall-binfmt:
	./scripts/uninstall-binfmt.sh

include $(DFILES)