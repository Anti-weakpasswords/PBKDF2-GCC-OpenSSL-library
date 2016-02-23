#RFC6070
./pbkdf2 -p 70617373776f7264 -s 73616c74 -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P hex -S hex
./pbkdf2 -p password -s 73616c74 -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P str -S hex
./pbkdf2 -p 70617373776f7264 -s salt -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P hex -S str
#RFC6070, also with NULL (0x00) characters in the middle
./pbkdf2 -p 7061737300776f7264 -s 7361006c74 -i 4096 -o 16 -a SHA-1 -e 56fa6aa75548099dcc37d7f03425e0c3 -P hex -S hex
