.PHONY: clean post_build run_phase1 run_tests

# To enable memory checks, uncomment the following line
# CFLAGS += -DENABLE_MEMORY_CHECKS


# To enable logging, uncomment the following line
# CFLAGS += -DENABLE_LOGGING 

# Build phase1 executable
phase1: fahe1.h fahe1.c phase1.c helper.c logger.c
	clang $(CFLAGS) -o phase1 -Wall fahe1.c phase1.c helper.c logger.c -lm -lcriterion -lssl -lcrypto

# Build testfahe1 executable for running tests
testfahe1: fahe1.h fahe1.c testfahe1.c helper.c logger.c
	clang $(CFLAGS) -o testfahe1 -Wall fahe1.c testfahe1.c helper.c logger.c -lm -lcriterion -lssl -lcrypto

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
