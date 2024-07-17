.PHONY: clean

# phase1 is the autograder that will run on submission
# it checks presence of functions, not correctness
phase1: fahe.h fahe.c phase1.c
	clang -o phase1 -Wall fahe.c phase1.c -lm -lcriterion

# test is for the tests you write in fahe
testfahe: fahe.h fahe.c fahetest.c
	clang -o fahetest -Wall fahe.c fahetest.c -lm -lcriterion

clean:
	rm -rf phase1 testfahe a.out
