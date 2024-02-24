CFLAGS  = -pg -g -Wall -std=c++14 -march=native

all: test trivial test_rasp trivial_rasp

test: test.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o test test.cpp -lsodium -loqs -lpthread -lm -lssl -lcrypto

test_rasp: test_rasp.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o test_rasp test_rasp.cpp -lsodium -loqs -lpthread -lm -lssl -lcrypto

trivial: trivial.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o trivial trivial.cpp -lsodium -loqs -lpthread -lm -lssl -lcrypto

trivial_rasp: trivial_rasp.cpp vacuum.h hashutil.h
	g++ $(CFLAGS) -Ofast -o trivial_rasp trivial_rasp.cpp -lsodium -loqs -lpthread -lm -lssl -lcrypto
        
clean:
	rm -f test trivial
