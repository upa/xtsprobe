CC = gcc
INCLUDE :=
LDFLAGS :=
CFLAGS := -g -Wall $(INCLUDE)

PROGNAME = xtsprobe

all: $(PROGNAME)

.c.o:
	$(CC) $< -o $@

clean:
	rm -rf *.o
	rm -rf $(PROGNAME)
