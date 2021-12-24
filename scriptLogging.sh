#!/bin/bash

echo -e "Enter the path where you want to create the log file (without the last slash): \c"
read path_name

cpuuse=$(cat /proc/loadavg | awk '{print $1}')

if [ -d $path_name ]
then
  touch $path_name/file.log
  echo "" > $path_name/file.log
  echo "CPU Current Usage is: $cpuuse%" >> $path_name/file.log
  echo "" >> $path_name/file.log
  echo "+------------------------------------------------------------------+" >> $path_name/file.log
  echo "Top CPU Process Using top command" >> $path_name/file.log
  echo "+------------------------------------------------------------------+" >> $path_name/file.log
  echo "$(top -bn1 | head -20)" >> $path_name/file.log
  echo "" >> $path_name/file.log
  echo "+------------------------------------------------------------------+" >> $path_name/file.log
  echo "Top CPU Process Using ps command" >> $path_name/file.log
  echo "+------------------------------------------------------------------+" >> $path_name/file.log
  echo "$(ps -eo pcpu,pid,user,args | sort -k 1 -r)" >> $path_name/file.log
else
  echo "Your directory path doesn't exist!"
fi


