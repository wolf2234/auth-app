#!/bin/bash

#/home/viktor/Desktop/test-dir/
#trap "echo You have just finished the operation; exit" 0 2 15

echo -e "Enter the path to the directory without the last slash: \c"
read dir_name

if [ -d $dir_name ]
then
  tar cpzvf $dir_name/backup.tgz --exclude=$dir_name /
else
  echo "The directory path doesn't exist!"
fi


