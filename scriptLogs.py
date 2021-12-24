import os

i = input('Enter the path to the log file with log file name: ')

if os.path.exists(i):
    log_file = open(i, 'r')
    for text in log_file:
        print(log_file.read())
    log_file.close()
else:
    print("Log file doesn't exist!")