#!/bin/bash

set -e
mkdir -p build
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Building sighthound for multiple platforms (Linux + macOS)..."
echo "Git commit: $GIT_HASH"
echo "Build date: $BUILD_DATE"

if ! docker buildx ls | grep -q "multiarch"; then
    echo "Creating multiarch builder..."
    docker buildx create --name multiarch --use
fi

docker buildx use multiarch

echo ""
echo "🐧 Building Linux binaries..."

# Build for x86_64 (AMD64) - most common for servers/EC2
echo "Building for linux/amd64 (x86_64)..."
docker buildx build \
  --platform linux/amd64 \
  --build-arg GIT_HASH="$GIT_HASH" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --target export \
  --output type=local,dest=./build/sighthound_linux_x64 \
  .

# Build for ARM64 (Apple Silicon, Graviton instances)
echo "Building for linux/arm64..."
docker buildx build \
  --platform linux/arm64 \
  --build-arg GIT_HASH="$GIT_HASH" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --target export \
  --output type=local,dest=./build/sighthound_linux_arm64 \
  .

echo ""
echo "🍎 Building macOS binary..."

# Build native macOS binary
export GIT_HASH
export BUILD_DATE
cargo build --release

# Create macOS release directory

mkdir -p ./build/sighthound_macos/
cp ./target/release/sighthound ./build/sighthound_macos/
cp -r rules/ ./build/sighthound_macos/

# Copy binaries to destination folder if specified
if [ -n "$SIGHTHOUND_DESTINATION_FOLDER" ]; then
    echo ""
    echo "📋 Copying binaries to destination folder: $SIGHTHOUND_DESTINATION_FOLDER"
    
    # Create destination directories if they don't exist
    mkdir -p "$SIGHTHOUND_DESTINATION_FOLDER/linux_x64"
    mkdir -p "$SIGHTHOUND_DESTINATION_FOLDER/linux_arm64"
    mkdir -p "$SIGHTHOUND_DESTINATION_FOLDER/osx"
    
    # Copy Linux x64 binary
    echo "Copying Linux x64 binary..."
    cp -r ./build/sighthound_linux_x64/* "$SIGHTHOUND_DESTINATION_FOLDER/linux_x64/"
    
    # Copy Linux ARM64 binary
    echo "Copying Linux ARM64 binary..."
    cp -r ./build/sighthound_linux_arm64/* "$SIGHTHOUND_DESTINATION_FOLDER/linux_arm64/"
    
    # Copy macOS binary
    echo "Copying macOS binary..."
    cp -r ./build/sighthound_macos/* "$SIGHTHOUND_DESTINATION_FOLDER/osx/"
    
    echo "✅ Binaries copied successfully to destination folder"
fi

echo ""
echo "✅ Multi-platform build completed!"
echo ""
echo "📁 Binaries created:"
echo "   ./build/sighthound_linux_x64/sighthound     - For x86_64 (Intel/AMD servers, most EC2)"
echo "   ./build/sighthound_linux_arm64/sighthound   - For ARM64 (Apple Silicon, Graviton instances)"
echo "   ./build/sighthound_macos/sighthound         - For macOS ($(uname -m))"