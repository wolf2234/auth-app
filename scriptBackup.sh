#!/bin/bash

#/home/viktor/Desktop/test-dir/
#trap "echo You have just finished the operation; exit" 0 2 15

echo -e "Enter the path to the directory without the last slash: \c"
read dir_name

if [ -d $dir_name ]
thenl
  tar cpzvf $dir_name/backup.tgz --exclude=/proc --exclude=/sys --exclude=/lost+found --exclude=$dir_name /
else
  echo "The directory path doesn't exist!"
fi


