import os
from pathlib import Path

def find_virtual_envs(directory):
    venv_names = {'.venv', 'venv', 'env'}
    venv_paths = []

    for root, dirs, _ in os.walk(directory):
        for dir_name in dirs:
            if dir_name in venv_names or 'venv' in dir_name.lower():
                venv_paths.append(os.path.join(root, dir_name))
        dirs[:] = [d for d in dirs if d not in venv_names]  # Don't recurse into found venvs
    
    return venv_paths

def find_pyenv_envs():
    pyenv_root = os.path.expanduser('~/.pyenv/versions')
    pyenv_paths = []

    if os.path.exists(pyenv_root):
        for version in os.listdir(pyenv_root):
            version_path = os.path.join(pyenv_root, version)
            if os.path.isdir(version_path):
                pyenv_paths.append(version_path)
    
    return pyenv_paths

def find_conda_envs():
    conda_root = os.path.expanduser('~/miniconda3/envs')
    conda_paths = []

    if os.path.exists(conda_root):
        for env in os.listdir(conda_root):
            env_path = os.path.join(conda_root, env)
            if os.path.isdir(env_path):
                conda_paths.append(env_path)
    
    return conda_paths

def save_to_file(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data:
            file.write(f"{item}\n")

if __name__ == "__main__":
    search_directory = str(Path.home())  # Start from user's home directory
    output_file = str(Path.home() / 'venv_paths.txt')
    
    print(f"Searching for virtual environments in {search_directory}...")
    venv_paths = find_virtual_envs(search_directory)
    pyenv_paths = find_pyenv_envs()
    conda_paths = find_conda_envs()
    
    all_paths = venv_paths + pyenv_paths + conda_paths
    save_to_file(output_file, all_paths)
    
    print(f"Found {len(all_paths)} virtual environments. Paths saved to {output_file}")