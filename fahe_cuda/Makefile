# Compiler
CC = nvcc

# Directories
SRC_DIR = src
TEST_DIR = tests
UNIT_TEST_DIR = $(TEST_DIR)/unit_tests
PERF_TEST_DIR = $(TEST_DIR)/perf_tests
BUILD_DIR = build
OUTPUT_DIR = output

# Flags
CFLAGS = -Xcompiler -Wall -std=c++14 -I$(SRC_DIR)
LDFLAGS = -L/path/to/criterion/lib -lcriterion -lssl -lcrypto

# Source files
SRC_FILES = $(SRC_DIR)/fahe1.cu \
            $(SRC_DIR)/fahe2.cu \
            $(SRC_DIR)/helper.cu \
            $(SRC_DIR)/logger.cu

# Unit test files
UNIT_TEST_FILES = $(UNIT_TEST_DIR)/phase1.cu \
                  $(UNIT_TEST_DIR)/phase2.cu \

# Performance test files
PERF_TEST_FILES = $(PERF_TEST_DIR)/testfahe1.cu \
                  $(PERF_TEST_DIR)/testfahe2.cu

# Object files
SRC_OBJS = $(patsubst $(SRC_DIR)/%.cu, $(BUILD_DIR)/%.o, $(SRC_FILES))
UNIT_TEST_OBJS = $(patsubst $(UNIT_TEST_DIR)/%.cu, $(BUILD_DIR)/%.o, $(UNIT_TEST_FILES))
PERF_TEST_OBJS = $(patsubst $(PERF_TEST_DIR)/%.cu, $(BUILD_DIR)/%.o, $(PERF_TEST_FILES))

# Targets
TARGETS = phase1 phase2 testfahe1 testfahe2

# Default Target
all: $(TARGETS)

# Build phase1 executable
phase1: $(BUILD_DIR)/phase1.o $(SRC_OBJS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/phase1.o $(SRC_OBJS)

# Build testfahe1 executable for running unit tests
testfahe1: $(BUILD_DIR)/testfahe1.o $(SRC_OBJS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/testfahe1.o $(SRC_OBJS)

# Build phase2 executable
phase2: $(BUILD_DIR)/phase2.o $(SRC_OBJS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/phase2.o $(SRC_OBJS)

# Build testfahe2 executable for running unit tests
testfahe2: $(BUILD_DIR)/testfahe2.o $(SRC_OBJS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/testfahe2.o $(SRC_OBJS)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cu
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Compile unit test files
$(BUILD_DIR)/%.o: $(UNIT_TEST_DIR)/%.cu
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Compile performance test files
$(BUILD_DIR)/%.o: $(PERF_TEST_DIR)/%.cu
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Clean build files
clean:
	@rm -rf $(BUILD_DIR) $(OUTPUT_DIR) $(TARGETS)

# Build and run the phase1 executable
run_phase1: phase1
	@./$(BUILD_DIR)/phase1
	@$(MAKE) --no-print-directory clean

# Build and run the testfahe1 executable for running fahe1 unit tests
run_fahe1_tests: testfahe1
	@./$(BUILD_DIR)/testfahe1
	@$(MAKE) --no-print-directory clean

# Build and run the phase2 executable
run_phase2: phase2
	@./$(BUILD_DIR)/phase2
	@$(MAKE) --no-print-directory clean

# Build and run the testfahe2 executable for running fahe2 unit tests
run_fahe2_tests: testfahe2
	@./$(BUILD_DIR)/testfahe2
	@$(MAKE) --no-print-directory clean

.PHONY: all clean run_phase1 run_fahe1_tests run_phase2 run_fahe2_tests