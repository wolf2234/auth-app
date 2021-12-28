#!/bin/bash

echo -e "Enter the path to your repository: \c"
read repository_name

echo -e "Enter the path to the Redis file along with the file name: \c"
read redis_name

git clone $repository_name

sudo cp $redis_name .

sudo apt install python-venv
python3 -m venv venv
source venv/bin/activate

rn=${repository_name##*//}
repository_path=${rn##*/}
name_folder=${repository_path%.git}

pip install -r ./$name_folder/requirements
python main.py # Command for run server
exit