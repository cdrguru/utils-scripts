#!/usr/bin/env python3
"""
Module to delete virtual environments found by find_virtual_environments.py.
"""

import os
import sys
import argparse
import logging
import shutil
from pathlib import Path

# Set up logging before importing send2trash
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

try:
    from send2trash import send2trash
except ImportError:
    send2trash = None
    logging.warning(
        "send2trash module not found. Install it via 'pip install send2trash' "
        "to enable moving files to Trash."
    )


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description='Delete virtual environments found by find_virtual_environments.py.'
    )
    parser.add_argument(
        '--input', type=str, default=str(Path.home() / 'venv_paths.txt'),
        help='Input file with paths to virtual environments'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Perform a dry run without deleting anything'
    )
    parser.add_argument(
        '--force', action='store_true',
        help='Delete without confirmation'
    )
    parser.add_argument(
        '--trash', action='store_true',
        help='Move to Trash instead of deleting permanently'
    )
    return parser.parse_args()


def load_paths(file_path):
    """
    Load virtual environment paths from the input file.

    Args:
        file_path (str): Path to the input file.

    Returns:
        list: List of virtual environment paths.
    """
    if not os.path.exists(file_path):
        logging.error(
            "Input file %s does not exist. Please run find_virtual_environments.py first.",
            file_path
        )
        sys.exit(1)
    with open(file_path, 'r', encoding='utf-8') as file:
        paths = [line.strip() for line in file if line.strip()]
    return paths


def confirm_deletion(selected_paths):
    """
    Confirm deletion of selected virtual environments.

    Args:
        selected_paths (list): List of paths to delete.

    Returns:
        bool: True if confirmed, False otherwise.
    """
    print("You have selected the following virtual environments to delete:")
    for path in selected_paths:
        print(f"- {path}")
    confirmation = input(
        "Are you sure you want to delete these virtual environments? (yes/no): "
    )
    return confirmation.lower() in ['yes', 'y']


def delete_paths(selected_paths, dry_run, trash):
    """
    Delete the selected virtual environments.

    Args:
        selected_paths (list): List of paths to delete.
        dry_run (bool): If True, perform a dry run.
        trash (bool): If True, move to Trash instead of deleting.

    Returns:
        list: List of successfully deleted paths.
    """
    deleted_paths = []
    for path in selected_paths:
        if os.path.exists(path) and os.path.isdir(path):
            try:
                if dry_run:
                    logging.info("[Dry Run] Would delete: %s", path)
                    continue
                if trash and send2trash:
                    # Move to Trash
                    send2trash(path)
                    logging.info("Moved to Trash: %s", path)
                else:
                    shutil.rmtree(path)
                    logging.info("Deleted: %s", path)
                deleted_paths.append(path)
            except OSError as e:
                logging.error("Error deleting %s: %s", path, e)
    return deleted_paths


def update_paths_file(file_path, deleted_paths):
    """
    Update the input file by removing deleted paths.

    Args:
        file_path (str): Path to the input file.
        deleted_paths (list): List of paths that were deleted.
    """
    remaining_paths = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            path = line.strip()
            if path not in deleted_paths:
                remaining_paths.append(path)
    with open(file_path, 'w', encoding='utf-8') as file:
        for path in remaining_paths:
            file.write("%s\n" % path)
    logging.info("Updated paths file %s", file_path)


def main():
    """
    Main function to execute the script.
    """
    args = parse_arguments()
    paths = load_paths(args.input)
    if not paths:
        logging.info("No virtual environments found to delete.")
        sys.exit(0)
    print("Virtual environments found:")
    for idx, path in enumerate(paths):
        print("%d. %s" % (idx + 1, path))
    selections = input(
        "Enter the numbers of environments to delete (comma-separated), 'all' to delete all, or 'none' to cancel: "
    )
    if selections.lower() == 'all':
        selected_paths = paths
    elif selections.lower() == 'none':
        logging.info("No environments selected. Exiting.")
        sys.exit(0)
    else:
        try:
            selected_indices = [
                int(i.strip()) - 1 for i in selections.split(',')
            ]
            selected_paths = [paths[i] for i in selected_indices]
        except (ValueError, IndexError) as e:
            logging.error("Invalid selection: %s", e)
            sys.exit(1)
    if not args.force and not confirm_deletion(selected_paths):
        logging.info("Deletion cancelled by user.")
        sys.exit(0)
    deleted_paths = delete_paths(selected_paths, args.dry_run, args.trash)
    if not args.dry_run:
        update_paths_file(args.input, deleted_paths)
    logging.info("Deleted %d virtual environments.", len(deleted_paths))


if __name__ == "__main__":
    main()
