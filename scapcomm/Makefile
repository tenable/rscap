
OBJS = scapcomm.o  rscap_cmd.o rscap_cmd_queue.o rscap_cmd_scap.o rscap_cmd_results.o rscap_cmd_remediation.o rscap_base64.o
CC=gcc -g -Wall -I../includes -I/opt/libev/include 
LIBS=-L../common -L/opt/libev/lib -lrscap  -lssl -lcrypto -lexpat -levhtp -levent -levent_openssl  -lrt

%.o: %.c
	$(CC) -c  $<

all: scapcomm

scapcomm: $(OBJS)
	$(CC) $(OBJS) -o scapcomm $(LIBS)

clean:
	rm -f $(OBJS) scapcomm
