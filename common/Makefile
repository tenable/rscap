
OBJS = rscap_alloc.o rscap_files.o rscap_stack.o rscap_strlcpy.o rscap_sys.o rscap_signature.o rscap_log.o \
rscap_untar.o rscap_sha1.o rscap_string.o rscap_hash.o rscap_cfg.o

CC=gcc -g -Wall -I../includes
AR=ar

%.o: %.c
	$(CC) -c  $<

all: $(OBJS)
	$(AR) -r librscap.a $(OBJS)
	ranlib librscap.a

clean:
	rm -f $(OBJS) librscap.a
