import os
import shutil
from pathlib import Path

def delete_virtual_envs(file_path, selected_paths):
    deleted_paths = []
    for path in selected_paths:
        path = path.strip()
        if os.path.exists(path) and os.path.isdir(path):
            try:
                shutil.rmtree(path)
                print(f"Deleted: {path}")
                deleted_paths.append(path)
            except PermissionError:
                print(f"Permission denied: {path}")
            except Exception as e:
                print(f"Error deleting {path}: {e}")
    
    # Update the file with remaining paths
    remaining_paths = [path for path in open(file_path, 'r', encoding='utf-8').readlines() if path.strip() not in deleted_paths]
    with open(file_path, 'w', encoding='utf-8') as file:
        for path in remaining_paths:
            file.write(path)

def select_envs_to_delete(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        paths = file.readlines()
    
    print("Select virtual environments to delete:")
    for i, path in enumerate(paths, 1):
        print(f"{i}. {path.strip()}")
    
    selections = input("Enter the numbers of environments to delete (comma-separated) or 'all': ")
    if selections.lower() == 'all':
        return paths
    else:
        selected_indices = [int(i) - 1 for i in selections.split(',')]
        return [paths[i] for i in selected_indices]

if __name__ == "__main__":
    input_file = str(Path.home() / 'venv_paths.txt')
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found. Run the search script first.")
        exit(1)

    selected_paths = select_envs_to_delete(input_file)
    
    confirmation = input("Are you sure you want to delete the selected virtual environments? (yes/no): ")
    if confirmation.lower() == 'yes':
        delete_virtual_envs(input_file, selected_paths)
    else:
        print("Operation cancelled.")