#!/bin/bash
set x
currHome=`pwd`
cd ${currHome}
echo "*"
echo "Monitoring.sh is running now....."
echo "*"

num=0

LOCKFILE=/var/lock/subsys/rtpp
PID_FILE=/var/run/rtpp.pid

PID=`ps -ef | grep -E "rtpp_monitor.sh" | grep -v "grep" | awk '{print $2}'`

for i in $PID
do
	num=$(( $num + 1 ))
done

if [ ${num} -le 2 ]
then
	echo "rtpp_monitor started successed!!!"
	sleep 3

	while [ 1 ]
	do
		ID0=`ps -ef | grep -E "/usr/local/sbin/rtpp" | grep -v "grep" | grep -v "rtpp_monitor.sh" | grep -v "dtach" | awk '{print $2}'`

		if [ "$ID0" = "" ]
		then
		echo "RtpProxy is restarting now....."
		rm -f $LOCKFILE
		rm -f $PID_FILE
		rm -f /tmp/dtach-rtpp 
		/etc/init.d/rtppmon start
		sleep 10
		echo "RtpRroxy restarted successed!!!"
		else
		sleep 5 
		fi
	done
else
	echo "There is another rtpp_monitor running now!!!"
	exit 0
fi

echo "rtpp_monitor have been stoped ..."

exit 0
