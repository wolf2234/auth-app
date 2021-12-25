#!/bin/bash

echo -e "Enter the path to your repository: \c"
read repository_name

echo -e "Enter the path where you want to extract the project: \c"
read path_name

echo -e "Enter the path to the Redis file along with the file name: \c"
read redis_name

python main.py # Command for run server

if [ -d $path_name ]
then
  git clone $repository_name $path_name
  mkdir -p $path_name/redis
  sudo cp $redis_name $path_name/redis
else
  echo "Your directory path doesn't exist!"
fi