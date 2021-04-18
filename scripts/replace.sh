#!/bin/bash

# Check variable
if [ $# -lt 3 ]
then
    echo "Too few variables"
    exit;
fi

FILE_PATH=$1
REPLACE_STR=$2
STR=$3

NUM=```cat $FILE_PATH | grep -o $REPLACE_STR | grep -c $REPLACE_STR```
sed -i "s/$REPLACE_STR/$STR/g" $FILE_PATH
echo "Replace: $NUM"
cat $FILE_PATH
