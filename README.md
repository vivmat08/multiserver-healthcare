# Multiserver Healthcare
This repository is an implementation of the [paper](https://doi.org/10.1007/s10796-021-10115-x
) titled "Privacy-Preserving Mutual Authentication and Key Agreement Scheme for Multi-Server Healthcare System"

The requirements for running this project are:
1. Cryptography library. To install it, simply run
```
pip3 install cryptography
```

All the below mentioned libraries are normally part of the core python3 distribution.

2. struct
3. threading
4. strings
5. sys
6. sockets
7. base64
8. ssl
9. secrets

There are 3 phases in this protocol:
1. Registration Phase
2. Service providing phase
3. Updation phase

Make sure you are running any code from its own directory.

Now, the first step before starting the implementation of this paper is to create a new cryptographic key pair and a certificate along with it ("certificate.pem" and "key.pem" files in the Registration Center directory). This step is necessary because the certificate and the key pair are local to all the systems and are generated using MAC Address of the system. Run the following command in terminal to generate this. 
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

This command should be run in the Registration Center directory

For the registration phase, first go to the registration directory, and run the regCenter_regPhase.py file by doing
```
python3 regCenter_regPhase.py
```

After the registration center is up and running, you can register any number of users and servers by running their respective registration files from their directory and providing an index for the user/server you are registering as a command line input.
```
python3 user_regPhase.py 1
python3 server_regPhase.py 1
```

After being done with registering the different servers and users, we can get started with providing service to users.
For this, first run the registration center updation file by running
```
python3 regCenter_update.py
```
This is necessary as each server and user updates their list of clients/smart card at the start of trying to get service.


Then make sure the servers are up and running by doing
```
python3 server_service.py 1
```
Make sure to provide an index to indicate which server is running.

Finally, now a customer can connect to the user by running
```
python3 user_service.py 1
```
Make sure to provide an index to indicate which user is running. 

Before updation can happen, the server/user will need to put in their credentials, which will be available in their respective credentials{index}.txt file.
