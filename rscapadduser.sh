#!/bin/sh


cleanup()
{
 stty echo
 exit 0
}

CONFIG=/opt/rscap/etc/rscap.cfg
case `id` in
 uid=0*)
  ;;
 *)
  echo "Must be root" 
  exit 1
  ;;
esac

trap cleanup EXIT

test -f "$CONFIG" ||
{
 echo "$CONFIG does not exist"
 exit 1
}

USERSDB=`cat $CONFIG|grep UsersDB|sed 's/=/ /'|awk '{print $2}'`
test -f "$USERSDB" ||
{
 echo "$USERSDB does not exist -- creating a new file"
}

echo -n "User to add: "
read user
if [ -f $USERSDB ]; 
then
 grep -q "$user =" $USERSDB && "User already exists in $USERSDB" && exit 1
fi


stty -echo
pw1=1
pw2=2
while [ "$pw1" != "$pw2" ];
do
 echo -n "Password: "
 read pw1
 echo
 echo -n "Password (again): "
 read pw2
 echo
 test "$pw1" != "$pw2" && echo "Passwords do not match!"
done
stty echo


salt=`dd if=/dev/urandom of=/dev/stdout bs=128 count=1 2>/dev/null|openssl sha1 |awk '{print $2}'`
pw=`cat << EOF > /dev/stdout | openssl sha1 | awk '{print $2}'
$salt$pw1
EOF`

echo $user = $salt:$pw >> $USERSDB
exit 0
