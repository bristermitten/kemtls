# Use specific platform to match your 'make' expectations (x86_64)
FROM --platform=linux/amd64 haskell:9.12

# 1. Install System Dependencies
# Nix inputs: pkgs.python3
RUN apt-get update && apt-get install -y \
    python3 \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# --- Build McTiny Library ---
WORKDIR /tmp/mctiny
COPY mctiny /tmp/mctiny

# Force clean build to ensure linux/amd64 objects
# Nix makeFlags: libmctiny.so mctiny-test
RUN make clean && make libmctiny.so mctiny-test

# --- Install Phase (Matches Nix Derivation) ---
# Nix installs to $out/lib, $out/include, $out/bin.
# We map this to /usr/local/ for system-wide visibility.

# 1. Libs
RUN cp libmctiny.so /usr/local/lib/

# 2. Headers (Explicitly matching Nix list)
RUN cp mctiny.h /usr/local/include/ && \
    cp crypto_kem_mceliece6960119.h /usr/local/include/
    # Note: If your Haskell FFI needs crypto_hash_shake256.h, add it here.
    # The Nix file implies only the two above are public API.

# 3. Binaries (Nix installs mctiny-test)
RUN cp mctiny-test /usr/local/bin/

# 4. Refresh Linker Cache so Haskell can find -lmctiny
RUN ldconfig

# --- Build Haskell Project ---
WORKDIR /app

# OPTIMIZATION: Cache Dependencies
# Copy only the cabal file first. If this hasn't changed, Docker uses cached layer.
COPY *.cabal /app/
RUN cabal update && \
    cabal build -j --only-dependencies \
    --extra-include-dirs=/usr/local/include \
    --extra-lib-dirs=/usr/local/lib

# Now copy source code and build the actual project
COPY . /app
RUN cabal build all -j \
    --extra-include-dirs=/usr/local/include \
    --extra-lib-dirs=/usr/local/lib

CMD ["bash"]