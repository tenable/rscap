
OBJS = scapuntar.o 
CC=gcc -g -Wall -I../includes -I/opt/libev/include 
LIBS=-L../common -L/opt/libev/lib -lrscap  -lssl -lcrypto -lexpat -levent -levent_openssl -levhtp

%.o: %.c
	$(CC) -c  $<

all: scapuntar

scapuntar: $(OBJS)
	$(CC) $(OBJS) -o scapuntar $(LIBS)

clean:
	rm -f $(OBJS) scapuntar
