
OBJS = scapassess.o scapassess_process.o scapassess_eval_xccdf.o
CC=gcc -g -Wall -I../includes
LIBS=-L../common -lrscap -lssl -lcrypto

%.o: %.c
	$(CC) -c  $<

all: scapassess

scapassess: $(OBJS)
	$(CC) $(OBJS) -o scapassess $(LIBS)

clean:
	rm -f $(OBJS) scapassess
