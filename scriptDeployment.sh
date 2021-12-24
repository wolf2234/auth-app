#!/bin/bash

echo -e "Enter the path to your repository: \c"
read repository_name

echo -e "Enter the path where you want to extract the project: \c"
read path_name

if [ -d $path_name ]
then
  git clone $repository_name $path_name
else
  echo "Your directory path doesn't exist!"
fi