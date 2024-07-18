.PHONY: clean

# it checks presence of functions, not correctness
phase1: fahe1.h fahe1.c phase1.c helper.c
	clang -o phase1 -Wall fahe1.c phase1.c helper.c -lm -lcriterion -lssl -lcrypto

# test is for the tests you write in fahe1
testfahe1: fahe1.h fahe1.c fahe1test.c helper.c
	clang -o fahe1test -Wall fahe1.c fahe1test.c helper.c -lm -lcriterion -lssl -lcrypto

clean:
	rm -rf phase1 testfahe1 a.out
