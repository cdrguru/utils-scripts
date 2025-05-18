#!/bin/bash

# Define the target directory
TARGET_DIR="/Users/pmd/Downloads"

# Print header
printf "%-20s %-10s %-10s\n" "Directory" "File Count" "Size"

# Loop through each subdirectory
for dir in "$TARGET_DIR"/*/; do
    # Check if it's a directory
    if [ -d "$dir" ]; then
        dir_name=$(basename "$dir")
        file_count=$(find "$dir" -type f | wc -l)
        dir_size=$(du -sh "$dir" | awk '{print $1}')
        printf "%-20s %-10s %-10s\n" "$dir_name" "$file_count" "$dir_size"
    fi
done