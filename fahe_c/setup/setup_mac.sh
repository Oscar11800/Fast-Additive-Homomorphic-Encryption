#!/bin/bash

# Check for Homebrew and install if it's not installed
if test ! $(which brew); then
  echo "Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Update Homebrew
brew update

# Install GCC (if needed)
brew install gcc

# Install OpenSSL
brew install openssl

# Install Criterion for unit testing
brew install criterion

echo "All dependencies have been installed."
