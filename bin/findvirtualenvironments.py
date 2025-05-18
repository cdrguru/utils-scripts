#!/usr/bin/env python3
"""
Module to find virtual environments on your system.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
import re


def setup_logging():
    """
    Set up logging configuration.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description='Find virtual environments on your system.'
    )
    parser.add_argument(
        '--root', type=str, default=str(Path.home()),
        help='Root directory to start search'
    )
    parser.add_argument(
        '--output', type=str, default=str(Path.home() / 'venv_paths.txt'),
        help='Output file to save paths'
    )
    parser.add_argument(
        '--exclude', nargs='*',
        default=[
            'node_modules', '.git', 'Library', 'Applications',
            'System', 'Volumes', 'venv_paths.txt'
        ],
        help='Directories to exclude from search'
    )
    parser.add_argument(
        '--max-depth', type=int, default=10,
        help='Maximum directory depth to search'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Perform a dry run without writing output file'
    )
    return parser.parse_args()


def is_virtual_env(dir_name):
    """
    Check if a directory name matches known virtual environment patterns.
    """
    patterns = [
        re.compile(r'^\.?venv$'),
        re.compile(r'^env$'),
        re.compile(r'^virtualenv$'),
        re.compile(r'^pyenv$'),
        re.compile(r'^node_modules$'),
        re.compile(r'^__pycache__$'),
        re.compile(r'^\.?tox$'),
    ]
    for pattern in patterns:
        if pattern.match(dir_name):
            return True
    return False


def find_virtual_envs(root_dir, exclude_dirs, max_depth):


    """
    Find virtual environments within the specified directory.

    Args:
        root_dir (str): The root directory to start the search.
        exclude_dirs (set): Set of directory names to exclude.
        max_depth (int): Maximum directory depth to search.

    Returns:
        list: List of paths to virtual environments.
    """
    venv_paths = []
    for current_root, dirs, _ in os.walk(
        root_dir, topdown=True, followlinks=False
    ):
        depth = current_root[len(root_dir):].count(os.sep)
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for dir_name in dirs[:]:
            full_path = os.path.join(current_root, dir_name)
            if is_virtual_env(dir_name):
                venv_paths.append(full_path)
                logging.info("Found virtual environment: %s", full_path)
                dirs.remove(dir_name)
    return venv_paths


def find_pyenv_envs():
    """
    Find pyenv virtual environments.

    Returns:
        list: List of pyenv environment paths.
    """
    pyenv_root = os.path.expanduser('~/.pyenv/versions')
    pyenv_paths = []
    if os.path.exists(pyenv_root):
        for version in os.listdir(pyenv_root):
            version_path = os.path.join(pyenv_root, version)
            if os.path.isdir(version_path):
                pyenv_paths.append(version_path)
                logging.info("Found pyenv environment: %s", version_path)
    return pyenv_paths


def find_conda_envs():
    """
    Find Conda virtual environments.

    Returns:
        list: List of Conda environment paths.
    """
    conda_root = os.path.expanduser('~/miniconda3/envs')
    conda_paths = []
    if os.path.exists(conda_root):
        for env in os.listdir(conda_root):
            env_path = os.path.join(conda_root, env)
            if os.path.isdir(env_path):
                conda_paths.append(env_path)
                logging.info("Found conda environment: %s", env_path)
    return conda_paths


def save_to_file(file_path, data):
    """
    Save list of paths to a file.

    Args:
        file_path (str): Path to the output file.
        data (list): List of paths to save.
    """
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data:
            file.write(f"{item}\n")
    logging.info("Saved %d paths to %s", len(data), file_path)


def main():
    """
    Main function to execute the script.
    """
    setup_logging()
    args = parse_arguments()
    logging.info("Searching for virtual environments in %s...", args.root)
    exclude_dirs = set(args.exclude)
    venv_paths = find_virtual_envs(args.root, exclude_dirs, args.max_depth)
    pyenv_paths = find_pyenv_envs()
    conda_paths = find_conda_envs()
    all_paths = venv_paths + pyenv_paths + conda_paths
    if not args.dry_run:
        save_to_file(args.output, all_paths)
    logging.info("Found %d virtual environments.", len(all_paths))


if __name__ == "__main__":
    main()
