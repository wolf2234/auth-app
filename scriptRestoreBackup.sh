#!/bin/bash

#/home/viktor/Desktop/test-dir/
#trap "echo You have just finished the operation; exit" 0 2 15

echo -e "Enter the path to the file along with the file name: \c"
read file_name

echo -e "Enter the path where you want to extract the archive: \c"
read path_name

if [ -e $file_name ] && [ -d $path_name ]
then
  tar xvpzf $file_name -C $path_name
else
  echo "The directory path doesn't exist!"
fi
