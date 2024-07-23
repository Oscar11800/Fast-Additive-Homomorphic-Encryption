.PHONY: clean post_build run_phase1 run_tests

# Build phase1 executable
phase1: fahe1.h fahe1.c phase1.c helper.c logger.c
	clang -o phase1 -Wall fahe1.c phase1.c helper.c logger.c -lm -lcriterion -lssl -lcrypto

# Build testfahe1 executable for running tests
testfahe1: fahe1optimized.h fahe1optimized.c testfahe1.c helper.c logger.c
	clang -o testfahe1 -Wall fahe1optimized.c testfahe1.c helper.c logger.c -lm -lcriterion -lssl -lcrypto

# Clean up generated files
clean:
	rm -rf phase1 testfahe1 a.out

# Run the clean target after each build
post_build:
	$(MAKE) clean

# Run the phase1 executable
run_phase1: phase1
	./phase1
	$(MAKE) clean

# Run the tests
run_tests: testfahe1
	./testfahe1
	$(MAKE) clean
