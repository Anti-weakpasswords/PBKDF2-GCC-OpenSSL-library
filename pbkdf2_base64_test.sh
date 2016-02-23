#RFC6070
#base64 to base64 from http://tomeko.net/online_tools/base64_to_base64.php?lang=en
./pbkdf2 -p cGFzc3dvcmQ= -s c2FsdA== -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P base64 -S base64
./pbkdf2 -p password -s c2FsdA== -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P str -S base64
./pbkdf2 -p cGFzc3dvcmQ= -s salt -i 1 -o 20 -a SHA-1 -e 0c60c80f961f0e71f3a9b524af6012062fe037a6 -P base64 -S str
./pbkdf2 -p cGFzcwB3b3Jk -s c2EAbHQ= -i 4096 -o 16 -a SHA-1 -e 56fa6aa75548099dcc37d7f03425e0c3 -P base64 -S base64
