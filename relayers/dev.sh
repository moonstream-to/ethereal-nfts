#!/usr/bin/env sh

# Compile application and run with provided arguments
set -e

PROGRAM_NAME="relayer_dev"

go build -o "$PROGRAM_NAME" .

./"$PROGRAM_NAME" "$@"
