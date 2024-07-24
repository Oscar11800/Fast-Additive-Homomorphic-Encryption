# Compiler
CC = clang

# Directories
SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
OUTPUT_DIR = output

# Flags
CFLAGS = -Wall -I$(SRC_DIR)
LDFLAGS = -lm -lcriterion -lssl -lcrypto

# Manually specify source and header files to include
SRC_FILES = $(SRC_DIR)/fahe1.c \
			$(SRC_DIR)/fahe2.c \
            $(SRC_DIR)/fahe1optimized.c \
            $(SRC_DIR)/helper.c \
            $(SRC_DIR)/logger.c \
            $(SRC_DIR)/threads.c

TEST_FILES = $(TEST_DIR)/phase1.c \
			 $(TEST_DIR)/phase2.c \
             $(TEST_DIR)/testfahe1.c

# Object files
SRC_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%.o, $(TEST_FILES))

# Targets
TARGETS = phase1 phase2 testfahe1 

# Default Target
all: $(TARGETS)

# Build phase1 executable
phase1: $(BUILD_DIR)/phase1.o $(SRC_OBJS)
	@$(CC) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/phase1.o $(SRC_OBJS) $(LDFLAGS)

# Build testfahe1 executable for running tests
testfahe1: $(BUILD_DIR)/testfahe1.o $(SRC_OBJS)
	@$(CC) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/testfahe1.o $(SRC_OBJS) $(LDFLAGS)

# Build phase2 executable
phase2: $(BUILD_DIR)/phase2.o $(SRC_OBJS)
	@$(CC) -o $(BUILD_DIR)/$@ $(BUILD_DIR)/phase2.o $(SRC_OBJS) $(LDFLAGS)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Compile test files
$(BUILD_DIR)/%.o: $(TEST_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Clean build files
clean:
	@rm -rf $(BUILD_DIR) $(OUTPUT_DIR) $(TARGETS)

# Run the clean target after each build
post_build: clean

# Build and run the phase1 executable
run_phase1: phase1
	@./$(BUILD_DIR)/phase1
	@$(MAKE) --no-print-directory clean

# Build and run the testfahe1 executable for running tests
run_fahe1_tests: testfahe1
	@./$(BUILD_DIR)/testfahe1
	@$(MAKE) --no-print-directory clean

# Build and run the phase1 executable
run_phase2: phase2
	@./$(BUILD_DIR)/phase2
	@$(MAKE) --no-print-directory clean

.PHONY: all clean post_build run_phase1 run_phase_2 run_fahe1_tests
