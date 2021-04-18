#!/bin/bash
NETWORK_INTERFACE=$1
LOGFILENAME=$2

# Check variable
if [ $# -lt 2 ]
then
    echo "Too few variables"
    exit;
fi

rm -f $LOGFILENAME
echo "Start"
# start listen
sudo build/main $NETWORK_INTERFACE $LOGFILENAME &
# Send http package
curl -s www.google.com.tw
sleep 2s
# stop listen
sudo kill -9 ```ps aux | grep build/main | awk '{print $2}'``` > /dev/null
echo "Complete"
 
