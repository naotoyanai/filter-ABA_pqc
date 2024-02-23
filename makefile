CFLAGS = -pg -g -Wall -std=c++14 -mpopcnt -march=native

all: test trivial test_rasp trivial_rasp

test: test.cpp vacuum.h hashutil.h
        g++ $(CFLAGS) -Ofast -o test test.cpp -lsodium -loqs -lpthread -lm

test_rasp: test_rasp.cpp vacuum.h hashutil.h
        g++ $(CFLAGS) -Ofast -o test_rasp test_rasp.cpp -lsodium -loqs -lpthread -lm

trivial: trivial.cpp vacuum.h hashutil.h
        g++ $(CFLAGS) -Ofast -o trivial trivial.cpp -lsodium -loqs -lpthread -lm

trivial_rasp: trivial_rasp.cpp vacuum.h hashutil.h
        g++ $(CFLAGS) -Ofast -o trivial_rasp trivial_rasp.cpp -lsodium -loqs -lpthread -lm


clean:
        rm -f test trivial

~                                                                        ~                  