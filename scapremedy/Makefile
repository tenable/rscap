
OBJS = scapremedy.o scapremedy_process.o  scapremedy_exec_script.o
CC=gcc -g -Wall -I../includes
LIBS=-L../common -lrscap -lssl -lcrypto

%.o: %.c
	$(CC) -c  $<

all: scapremedy

scapremedy: $(OBJS)
	$(CC) $(OBJS) -o scapremedy $(LIBS)

clean:
	rm -f $(OBJS) scapremedy
