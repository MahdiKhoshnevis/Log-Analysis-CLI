import os

# Define the path to the log file
log_file_path = os.path.join("access.log", "access.log")

# Open the file using a context manager.
# reading line-by-line using a generator/iterator prevents loading the entire file into memory.
try:
    with open(log_file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            # Strip trailing newline characters
            clean_line = line.rstrip("\n")
            
            # Print the line or perform any line-by-line processing here
            print(clean_line)

except FileNotFoundError:
    print(f"Error: The file at {log_file_path} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
