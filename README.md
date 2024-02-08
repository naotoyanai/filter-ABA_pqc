# filter-ABA_pqc

### Install `liboqs` library
Recommend to build the liboqs library by the following command: 
1. ``git clone --single-branch https://github.com/open-quantum-safe/liboqs.git``
2. ``cd liboqs/``
3. ``mkdir build``
4. ``cd build``
5. ``cmake -DOQS_USE_OPENSSL=0 ..``
6. ``make all``
7. ``sudo make install``

### How to compile 
``gcc example_sig.c -loqs -lpthread -lm``
