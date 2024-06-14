import os
import time

def get_file_creation_time(file_path):
    # Get the file's status
    file_stats = os.stat(file_path)
    
    # Get the creation time
    creation_time = file_stats.st_ctime
    
    # Convert the timestamp to a human-readable format
    creation_time_human_readable = time.ctime(creation_time)
    
    return creation_time_human_readable

file_path = 'ARCS.CSV'  # Replace with your file path
print(f"Creation time of '{file_path}': {get_file_creation_time(file_path)}")

