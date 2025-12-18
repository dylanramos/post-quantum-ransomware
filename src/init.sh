#!/bin/bash

# Remove the folder if it already exists
if [ -d "test" ]; then
  rm -rf test
fi

# Create the folder and add 3 files
mkdir test
echo "This is the content of file1." > test/file1.txt
echo "This is the content of file2." > test/file2.dat
echo "This is the content of file3." > test/file3.html

# Create a subfolder and add 2 more files
mkdir -p test/subfolder
echo "This is the content of file4 in subfolder." > test/subfolder/file4.exe
echo "This is the content of file5 in subfolder." > test/subfolder/file5.png

echo "Setup complete."
