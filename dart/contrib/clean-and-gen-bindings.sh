#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "Deleting generated Dart files in lib/src/generated..."
rm -rf lib/src/generated/*

echo "Deleting generated Rust file rust/src/frb_generated.rs..."
: > rust/src/frb_generated.rs

echo "Running flutter clean..."
flutter clean

echo "Running flutter pub get..."
flutter pub get

echo "Running make all..."
make all

echo "Done."
