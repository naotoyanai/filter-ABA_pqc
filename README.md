# filter-ABA_pqc

### List of Pre-installed libraries
1. Vacuum filter (https://github.com/wuwuz/Vacuum-Filter)
2. liboqs library (https://github.com/open-quantum-safe/liboqs)

#### Install `liboqs` library
Recommend to build the liboqs library by the following command: 
1. ``git clone --single-branch https://github.com/open-quantum-safe/liboqs.git``
2. ``cd liboqs/``
3. ``mkdir build``
4. ``cd build``
5. ``cmake -DOQS_USE_OPENSSL=0 ..``
6. ``make all``
7. ``sudo make install``

### How to compile and execute
1. type ``git clone https://github.com/wuwuz/Vacuum-Filter``.
2. Relace ``test.cpp`` and ``makefile" in `Vacuumfilter` with the file in this repository. 
3. Put ``trivial.cpp`` in the same repository. 
4. ``make test`` for the generic construction or ``make trivial`` for the trivial construction

### Direct complile option from the liboqs library
``gcc example_sig.c -loqs -lpthread -lm``
