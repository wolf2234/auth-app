#!/bin/bash

echo -e "Enter the path where you want to create the log file (without the last slash): \c"
read path_name

cpuuse=$(cat /proc/loadavg | awk '{print $1}')

# grab the second line of the ouput produced by the command: free -g (displays output in Gb)
secondLine=$(free -g | sed -n '2p')

#split the string in secondLine into an array
read -ra ADDR <<< "$secondLine"

#get the total RAM from array
totalRam="${ADDR[1]}"

#get the used RAM from array
usedRam="${ADDR[2]}"

# calculate and display the percentage
pct="$(($usedRam*100/$totalRam))"

trap "echo Recording ended with ctrl + c command; exit" 0 2 15

if [ -d $path_name ]
then
  while true
  do
    echo "Date         Time       CPU  RAM" >> $path_name/file.log
    echo "`date "+%d/%m/%Y   %H:%M:%S"`   $cpuuse%  $pct%" >> $path_name/file.log
    echo "" >> $path_name/file.log
    echo "             Processes" >> $path_name/file.log
    echo "$(ps -F)" >> $path_name/file.log
    echo "+------------------------------------------------------------------+" >> $path_name/file.log
    sleep 300  # Information is recorded every 5 minutes
  done
else
  echo "Your directory path doesn't exist!"
fi
