#!/bin/bash

# Update package lists
sudo apt-get update

# Install GCC and essential build tools
sudo apt-get install -y build-essential

# Install OpenSSL
sudo apt-get install -y libssl-dev

# Install Criterion for unit testing
sudo apt-get install -y libcriterion-dev

echo "All dependencies have been installed."
