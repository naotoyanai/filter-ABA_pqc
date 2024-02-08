# filter-ABA_pqc

# install `liboqs`
Recommend to build the liboqs library by the following command: 
- $ mkdir ~/oqs
- $ cd ~/oqs
- $ git clone --single-branch https://github.com/open-quantum-safe/liboqs.git
- $ cd liboqs/
- $ git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
- $ mkdir build
- $ cd build
- $ cmake -DOQS_USE_OPENSSL=0 ..
- $ make all
- $ sudo make install
