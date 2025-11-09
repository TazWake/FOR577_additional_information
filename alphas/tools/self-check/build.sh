#!/bin/bash
# self-check build script
# Assembles, links, and strips the binary to create a minimal static ELF

set -e  # Exit on error

echo "[*] Building self-check..."

# Check for NASM
if ! command -v nasm &> /dev/null; then
    echo "[!] ERROR: nasm not found. Please install NASM assembler."
    echo "    Ubuntu/Debian: sudo apt-get install nasm"
    echo "    Fedora/RHEL: sudo dnf install nasm"
    exit 1
fi

# Assemble with NASM (x86-64 ELF object)
echo "[*] Assembling src/self-check.asm..."
nasm -felf64 src/self-check.asm -o self-check.o

# Link statically with no standard library
echo "[*] Linking statically..."
ld -static -nostdlib -o self-check self-check.o

# Strip symbols to minimize size
echo "[*] Stripping symbols..."
strip self-check

# Report size
if command -v stat &> /dev/null; then
    # Try Linux stat first
    SIZE=$(stat -c%s self-check 2>/dev/null || stat -f%z self-check 2>/dev/null)
    echo "[*] Binary size: $SIZE bytes"

    # Check against 16KB limit
    if [ "$SIZE" -gt 16384 ]; then
        echo "[!] WARNING: Binary exceeds 16KB limit (target: <16384 bytes)"
        echo "[!] Current size: $SIZE bytes"
    else
        echo "[+] SUCCESS: Binary is within size limit (<16KB)"
    fi
else
    echo "[*] Binary created: self-check"
    ls -lh self-check
fi

# Verify it's statically linked
echo "[*] Verifying static linking..."
if command -v ldd &> /dev/null; then
    if ldd self-check 2>&1 | grep -q "not a dynamic executable"; then
        echo "[+] Confirmed: Static binary (no dynamic dependencies)"
    else
        echo "[!] WARNING: Binary appears to have dynamic dependencies:"
        ldd self-check
    fi
fi

# Verify it's an ELF executable
if command -v file &> /dev/null; then
    echo "[*] Binary type:"
    file self-check
fi

echo ""
echo "[+] Build complete! Binary: self-check"
echo "[*] Usage: ./self-check"
echo ""
