#!/bin/bash
#echo $#
#echo $@

#if (("$#" < 1)) ; then
#echo "Please input commit info"
#exit
#else
#echo "commit is " $1
#make clean
#git add .
#git commit -m "$1"
#git push origin OBD
#fi

#make clean
#cd OBD_Report
git fetch --all
git reset --hard origin/master


