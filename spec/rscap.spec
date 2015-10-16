Summary: rscap listeners
Name: rscap
Version: 1.0.0
Release: 14
License: GPL
Group: Administration Tools
#URL: 
Source0: rscap-latest.tar.gz
Source1: rscap
Packager: Mr Package <mrpackage@tenable.com>
BuildRoot: /var/tmp/%{name}-buildroot
Requires: openssl zlib openscap-utils
%description
rscap daemons to remotely perform openscap checks

%prep

%build
test -d $RPM_BUILD_ROOT || mkdir $RPM_BUILD_ROOT
cp /usr/src/redhat/SOURCES/rscap-latest.tar.gz $RPM_BUILD_ROOT
cp /usr/src/redhat/SOURCES/rscap $RPM_BUILD_ROOT

%install
test -f $RPM_BUILD_ROOT/rscap-latest.tar.gz || cp /usr/src/redhat/SOURCES/rscap-latest.tar.gz $RPM_BUILD_ROOT
test -f $RPM_BUILD_ROOT/rscap || cp /usr/src/redhat/SOURCES/rscap $RPM_BUILD_ROOT
tar -zxvpf $RPM_BUILD_ROOT/rscap-latest.tar.gz -C $RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT/rscap-latest.tar.gz
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mv $RPM_BUILD_ROOT/rscap $RPM_BUILD_ROOT/etc/rc.d/init.d/
chmod +x $RPM_BUILD_ROOT/etc/rc.d/init.d/rscap

chown -R 0:0 $RPM_BUILD_ROOT

%pre
test -x /etc/rc.d/init.d/rscap && /sbin/service rscap stop
exit 0

%preun
killall scapcomm scapassess
exit 0

%postun

%post 
/usr/sbin/adduser -r scapcomm 2>/dev/null
/bin/chown -R scapcomm:scapcomm /var/opt/rscap/*

exit 0

%clean
rm -rf $RPM_BUILD_ROOT

%files
/opt/rscap
/var/opt/rscap
/etc/rc.d/init.d/rscap


