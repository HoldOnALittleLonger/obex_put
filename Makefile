all: obex_put

vpath	%.c src/
vpath	%.h inc/

CC := gcc
override CFLAGS += -std=c23 -Iinc/
SHARED_LIBS := bluetooth

%.o:%.c
	$(CC) -o $@ $(CFLAGS) -c $<

obex_put: main.o obex_impl.o obex_layout.o obex_helpers.o mime_type.o
	$(CC) -o $@ $(CFLAGS) $^ -l$(SHARED_LIBS)

.PHONY: clean
clean:
	rm -f *.o
