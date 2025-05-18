import os
from pathlib import Path

def find_virtual_envs(directory):
    venv_names = {'.venv', 'venv', 'env'}
    venv_paths = []

    for root, dirs, _ in os.walk(directory):
        for dir_name in dirs:
            if dir_name in venv_names or 'venv' in dir_name.lower():
                venv_paths.append(os.path.join(root, dir_name))
        # Do not recurse into directories that are found virtual environments
        dirs[:] = [d for d in dirs if d not in venv_names]
    
    return venv_paths

def save_to_file(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data:
            file.write(f"{item}\n")

if __name__ == "__main__":
    search_directory = str(Path.home())  # Start from user's home directory
    output_file = str(Path.home() / 'venv_paths.txt')
    
    print(f"Searching for virtual environments in {search_directory}...")
    venv_paths = find_virtual_envs(search_directory)
    save_to_file(output_file, venv_paths)
    print(f"Found {len(venv_paths)} virtual environments. Paths saved to {output_file}")