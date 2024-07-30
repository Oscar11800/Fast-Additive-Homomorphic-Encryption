# Check if Chocolatey is installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force;
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor  [System.Net.SecurityProtocolType]::Tls12;
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'));
}

# Install GCC (via MinGW) and Make
choco install mingw
choco install make

# Install OpenSSL
choco install openssl

# Install Criterion (if available via Chocolatey)
# Note: Criterion might not be available via Chocolatey, provide manual instructions if necessary
choco install criterion

Write-Host "All dependencies have been installed."
