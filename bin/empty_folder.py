"""
Empty Folder Finder Utility

This script lists and optionally deletes empty folders within the specified directory.

Dependencies:
    - None (uses Python's standard library)

Usage Examples:
    1. List empty folders in the current directory:
        python empty_folder.py

    2. Recursively list empty folders:
        python empty_folder.py -r

    3. Delete empty folders with confirmation:
        python empty_folder.py -r --delete

    4. Delete empty folders without confirmation:
        python empty_folder.py -r --delete --force

    5. Simulate deletion (dry-run):
        python empty_folder.py -r --delete --dry-run
"""

import os
import sys
import argparse
import logging
from typing import List, Optional

DEFAULT_LOG_LEVEL = "INFO"
CONFIRMATION_PROMPT = "Delete folder '%s'? [y/N] "

def configure_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Configures logging to display messages to the console and optionally to a log file.

    Args:
        log_level (str): Logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file (str, optional): Path to the log file. If None, logs only to console.
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to set up file logging: {e}")
            sys.exit(1)


def is_folder_empty(folder_path: str) -> bool:
    """
    Checks if a folder is empty.

    Args:
        folder_path (str): Path to the folder.

    Returns:
        bool: True if the folder is empty, False otherwise.

    Raises:
        PermissionError: If access to the folder is denied.
    """
    try:
        with os.scandir(folder_path) as it:
            for entry in it:
                logging.debug("Found entry '%s' in folder '%s'", entry.name, folder_path)
                return False
        logging.debug(f"Folder '{folder_path}' is empty.")
        return True
    except PermissionError as e:
        logging.error(f"Permission denied accessing folder '{folder_path}': {e}")
        return False
    except (OSError, IOError) as e:
        logging.error("Error accessing folder '%s': %s", folder_path, e)
        return False


def list_empty_folders(directory: str, recursive: bool = False) -> List[str]:
    """
    Lists all empty folders within the specified directory.

    Args:
        directory (str): Path to the directory to scan.
        recursive (bool): Whether to scan subdirectories recursively.

    Returns:
        List[str]: A list of paths to empty folders.
    """
    empty_folders = []

    if recursive:
        logging.debug(f"Starting recursive scan in directory '{directory}'.")
        for root, dirs, files in os.walk(directory):
            for dir_name in dirs:
                folder_path = os.path.join(root, dir_name)
                logging.debug(f"Checking folder '{folder_path}'.")
                if is_folder_empty(folder_path):
                    empty_folders.append(folder_path)
    else:
        logging.debug(f"Starting non-recursive scan in directory '{directory}'.")
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if entry.is_dir():
                        folder_path = entry.path
                        logging.debug(f"Checking folder '{folder_path}'.")
                        if is_folder_empty(folder_path):
                            empty_folders.append(folder_path)
        except PermissionError as e:
            logging.error(f"Permission denied accessing directory '{directory}': {e}")
        except Exception as e:
            logging.error(f"Error accessing directory '{directory}': {e}")

    return empty_folders


def delete_empty_folders(empty_folders: List[str], force: bool = False, dry_run: bool = False) -> None:
    """
    Delete empty folders with optional confirmation.

    Args:
        empty_folders (List[str]): List of empty folder paths to delete
        force (bool): Skip confirmation if True
        dry_run (bool): Simulate deletion without actually removing folders
    """
    if not empty_folders:
        return

    for folder in empty_folders:
        try:
            if dry_run:
                logging.info(f"[DRY-RUN] Would delete: {folder}")
                continue

            if force:
                logging.info(f"Deleting: {folder}")
                if not dry_run:
                    os.rmdir(folder)
            else:
                response = input(CONFIRMATION_PROMPT % folder).lower()
                if response == 'y':
                    logging.info(f"Deleting: {folder}")
                    if not dry_run:
                        os.rmdir(folder)
                else:
                    logging.info(f"Skipping: {folder}")
        except Exception as e:
            logging.error(f"Failed to delete '{folder}': {e}")


def main():
    parser = argparse.ArgumentParser(
        description="List and optionally delete empty folders in the specified directory."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Path to the directory to scan for empty folders (default: current directory)."
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories for empty folders."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)."
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to the log file. If not specified, logs are printed to console only."
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete the empty folders found."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Delete empty folders without confirmation (use with --delete)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the deletion process without making any changes."
    )
    args = parser.parse_args()

    # Configure logging
    configure_logging(log_level=args.log_level, log_file=args.log_file)

    # Determine the directory to scan
    directory = os.path.abspath(args.directory)
    logging.info(f"Scanning directory: {directory}")
    logging.info(f"Recursive scan: {'Enabled' if args.recursive else 'Disabled'}")

    # Check if the directory exists
    if not os.path.isdir(directory):
        logging.error(f"The path '{directory}' is not a valid directory.")
        sys.exit(1)

    # List empty folders
    empty_folders = list_empty_folders(directory, recursive=args.recursive)

    # Output the results
    if empty_folders:
        print("\nEmpty Folders:")
        for folder in empty_folders:
            print(f" - {folder}")
        logging.info(f"Total empty folders found: {len(empty_folders)}")

        if args.delete:
            delete_empty_folders(empty_folders, force=args.force, dry_run=args.dry_run)
    else:
        print("\nNo empty folders found.")
        logging.info("No empty folders found.")


if __name__ == "__main__":
    main()