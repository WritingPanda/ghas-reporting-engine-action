#!/bin/bash
set -e

echo "Building GHAS Reporting Engine..."

# Clean dist directory
rm -rf dist
mkdir -p dist

echo "Running TypeScript compiler..."
npx tsc

echo "Contents of dist directory:"
ls -la dist/

echo "Bundling with ncc..."
npx ncc build dist/index.js -o dist --target node20

echo "Final contents:"
ls -la dist/

echo "Build complete!"
