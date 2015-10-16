
all:
	cd common && $(MAKE) 
	cd scapassess && $(MAKE) 
	cd scapcomm && $(MAKE) 
	cd scapmktar && $(MAKE) 
	cd scapuntar && $(MAKE) 
	cd scapremedy && $(MAKE) 

clean:
	cd common && $(MAKE) clean
	cd scapassess && $(MAKE) clean
	cd scapcomm && $(MAKE) clean
	cd scapmktar && $(MAKE) clean
	cd scapuntar && $(MAKE) clean
	cd scapremedy && $(MAKE) clean

install: all
	install -m 0755 scapassess/scapassess /opt/rscap/bin/scapassess
	install -m 0755 scapcomm/scapcomm /opt/rscap/bin/scapcomm
	install -m 0755 scapmktar/scapmktar /opt/rscap/bin/scapmktar
	install -m 0755 scapuntar/scapuntar  /opt/rscap/bin/scapuntar
	install -m 0755 scapremedy/scapremedy /opt/rscap/bin/scapremedy
	install -m 0755 rscapadduser.sh /opt/rscap/bin/rscapadduser.sh
	mkdir -p /opt/rscap/share/
	rm -rf /opt/rscap/share/rscap
	cp -r sample /opt/rscap/share/rscap
