# filter-ABA_pqc

This repository is an implementation of an extended version of our ISPEC paper: 
Yohei Watanabe, Naoto Yanai, Junji Shikata: IoT-REX: A Secure Remote-Control System for IoT Devices from Centralized Multi-designated Verifier Signatures. ISPEC 2023: 105-122. 
https://link.springer.com/chapter/10.1007/978-981-99-7032-2_7

The main parts of our code is with the Dilithium2 signatures. 
We also release the code with Falcon-512.

### List of Pre-installed libraries
1. Vacuum filter (https://github.com/wuwuz/Vacuum-Filter)
2. liboqs library (https://github.com/open-quantum-safe/liboqs) version 0.9.0
3. libsodium library (https://libsodium.gitbook.io/doc/) version 1.0.18-stable

#### Install `liboqs` library
Recommend to build the liboqs library by the following command: 
1. `git clone --single-branch https://github.com/open-quantum-safe/liboqs.git`
2. `cd liboqs/`
3. `mkdir build`
4. `cd build`
5. `cmake -DOQS_USE_OPENSSL=0 ..`
6. `make all`
7. `sudo make install`

### How to compile and execute
1. type `git clone https://github.com/wuwuz/Vacuum-Filter`.
2. Relace ``test.cpp`` and ``makefile" in `Vacuumfilter` with the file in this repository. 
3. Put ``trivial.cpp`` in the same repository. 
4. `make test` for the generic construction or ``make trivial`` for the trivial construction
5. `make falcon` for the generic construction with Falcon-512.

### Direct complile option from the liboqs library
``gcc example_sig.c -loqs -lpthread -lm``


### Execute Anonymous Broadcast Authentication
1. Type `gcc aba-weak.c -lcrypto -lm` on ``aba-weak.c`` 
2. Run an executable file output by gcc
