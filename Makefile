CC         = gcc
SOURCEDIR  = source
INCLUDEDIR = include
BINNAME    = 9aout
LDFLAGS    = -Wl,-Ttext-segment,0x700000000000 -pthread
CFLAGS     = -Wall -Wno-misleading-indentation -Wno-parentheses -fomit-frame-pointer -I$(INCLUDEDIR)

CFILES := $(shell find $(SOURCEDIR) -name '*.c' | sort -n)
DFILES := $(CFILES:%.c=%.d)
OFILES := $(foreach filepath,$(CFILES),$(notdir $(filepath:%.c=%.o)))

ifdef DEBUG
	CFLAGS += -g -DDEBUG
endif

ifdef LINUX_FALLBACK
	CFLAGS += -DLINUX_FALLBACK
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