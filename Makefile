all: obex_put

vpath	%.c src/
vpath	%.h inc/

CC := gcc
override CFLAGS += -std=c23 -Iinc/
SHARED_LIBS := bluetooth
OBJECTS := main.o obex_impl.o obex_layout.o obex_helpers.o
OBJECTS += obex_agent.o obex_agent_data.o mime_type.o

%.o:%.c
	$(CC) -o $@ $(CFLAGS) -c $<

obex_put: $(OBJECTS)
	$(CC) -o $@ $(CFLAGS) $^ -l$(SHARED_LIBS)
	install $@ bin/

.PHONY: clean
clean:
	rm -f *.o obex_put
