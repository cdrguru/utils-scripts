"""
File Organization Utility

This script organizes files within a specified directory by sorting them into subdirectories
based on their file types. It determines file types using both content and file extensions
and provides options for recursive organization, dry runs, custom logging configurations,
and more.

Dependencies:
    - filetype: Install via `pip install filetype`

Usage Examples:
    1. Organize files in the "Downloads" directory recursively with default settings:
        python organize_files.py /path/to/Downloads -r

    2. Perform a dry run to see what changes would be made without actually moving any files:
        python organize_files.py /path/to/Downloads --dry-run

    3. Organize files using only extension-based detection and specify a custom log file:
        python organize_files.py /path/to/Downloads --use-extension-only --log-file my_log.log

    4. Set the logging level to DEBUG for more verbose output:
        python organize_files.py /path/to/Downloads --log-level DEBUG
"""

import os
import sys
import argparse
import logging
import shutil
from collections import defaultdict
from typing import Optional, List, Dict
from datetime import datetime

import filetype

# Constants
DEFAULT_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
UNKNOWN_TYPE = "Unknown"


def configure_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Configures logging to write to both file and console.

    Args:
        log_level (str): Logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file (Optional[str]): Path to the log file. If None, logs only to console.
    """
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=DEFAULT_LOG_FORMAT,
        handlers=handlers
    )


def get_file_type(file_path: str, use_content: bool = True) -> str:
    """
    Determines file type by content or extension.

    Args:
        file_path (str): Path to the file.
        use_content (bool): Whether to use content-based detection.

    Returns:
        str: File type in uppercase or 'Unknown'.
    """
    try:
        if use_content:
            kind = filetype.guess(file_path)
            if kind:
                detected_type = kind.extension.upper()
                logging.debug("Detected type for '%s': %s", file_path, detected_type)
                return detected_type

        # Extension-based fallback
        _, ext = os.path.splitext(file_path)
        detected_type = ext[1:].upper() if ext else UNKNOWN_TYPE
        logging.debug("Fallback detected type for '%s': %s", file_path, detected_type)
        return detected_type

    except OSError as e:
        logging.error("Error detecting file type for %s: %s", file_path, e)
        return UNKNOWN_TYPE


def create_directory(directory_path: str) -> None:
    """
    Creates a directory if it doesn't already exist.

    Args:
        directory_path (str): Path to the directory to create.
    """
    try:
        os.makedirs(directory_path, exist_ok=True)
        logging.debug("Directory ensured: %s", directory_path)
    except Exception as e:
        logging.error("Error creating directory %s: %s", directory_path, e)


def move_file(src_path: str, dest_dir: str, dry_run: bool = False) -> None:
    """
    Moves a file to its destination directory, handling name conflicts by appending
    the creation date and a counter to the filename.

    Args:
        src_path (str): Source file path.
        dest_dir (str): Destination directory path.
        dry_run (bool): If True, only simulate the move.
    """
    filename = os.path.basename(src_path)
    dest_path = os.path.join(dest_dir, filename)

    if os.path.exists(dest_path):
        try:
            # Get creation date
            creation_time = os.path.getctime(src_path)
            creation_date = datetime.fromtimestamp(creation_time).strftime("%Y%m%d")
        except Exception as e:
            logging.error(f"Error getting creation date for {src_path}: {e}")
            creation_date = "00000000"

        base, extension = os.path.splitext(dest_path)
        counter = 1
        new_dest_path = f"{base}_{creation_date}_{counter:02d}{extension}"
        while os.path.exists(new_dest_path):
            counter += 1
            new_dest_path = f"{base}_{creation_date}_{counter:02d}{extension}"
        
        logging.warning(
            "Destination file %s already exists. Renaming to %s.",
            dest_path,
            new_dest_path
        )
        dest_path = new_dest_path

    logging.info("Moving file %s to %s", src_path, dest_path)
    if not dry_run:
        try:
            shutil.move(src_path, dest_path)
        except Exception as e:
            logging.error("Failed to move %s to %s: %s", src_path, dest_path, e)


def organize_files(
    directory: str,
    recursive: bool = False,
    dry_run: bool = False,
    use_content: bool = True,
    skip_hidden: bool = False
) -> None:
    """
    Organizes files into subdirectories based on their type.

    Args:
        directory (str): Target directory path.
        recursive (bool): Whether to process subdirectories.
        dry_run (bool): If True, simulate without making changes.
        use_content (bool): Whether to use content-based type detection.
        skip_hidden (bool): Whether to skip hidden files.
    """
    file_types: Dict[str, List[str]] = defaultdict(list)

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if skip_hidden and filename.startswith('.'):
                logging.debug("Skipping hidden file: %s", filename)
                continue

            file_path = os.path.join(root, filename)

            if not os.path.isfile(file_path):
                logging.debug("Skipping non-file: %s", file_path)
                continue

            file_type = get_file_type(file_path, use_content)
            file_types[file_type].append(file_path)

        if not recursive:
            break  # Do not traverse into subdirectories

    for ftype, files in file_types.items():
        target_dir = os.path.join(directory, ftype) if ftype != UNKNOWN_TYPE else os.path.join(directory, "Unknown")
        create_directory(target_dir)

        for file_path in files:
            if os.path.abspath(file_path).startswith(os.path.abspath(target_dir)):
                logging.debug("File '%s' is already in '%s'. Skipping.", file_path, target_dir)
                continue

            move_file(file_path, target_dir, dry_run)


def main():
    parser = argparse.ArgumentParser(
        description="Organize files into folders based on their types."
    )
    parser.add_argument(
        "directory",
        help="Path to the directory to organize."
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively organize files in subdirectories."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the organization without making any changes."
    )
    parser.add_argument(
        "--use-extension-only",
        action="store_true",
        help="Use only file extensions for type detection, ignoring file content."
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
        "--skip-hidden",
        action="store_true",
        help="Skip hidden files during organization."
    )

    args = parser.parse_args()

    configure_logging(log_level=args.log_level, log_file=args.log_file)

    directory = args.directory
    recursive = args.recursive
    dry_run = args.dry_run
    use_content = not args.use_extension_only
    skip_hidden = args.skip_hidden

    if not os.path.isdir(directory):
        logging.error("The path '%s' is not a valid directory.", directory)
        sys.exit(1)

    logging.info("Starting file organization.")
    logging.info("Directory: %s", directory)
    logging.info("Recursive: %s", "Enabled" if recursive else "Disabled")
    logging.info("Dry-Run: %s", "Enabled" if dry_run else "Disabled")
    logging.info("Use Content-Based Detection: %s", "Yes" if use_content else "No")
    logging.info("Skip Hidden Files: %s", "Yes" if skip_hidden else "No")

    try:
        organize_files(
            directory=directory,
            recursive=recursive,
            dry_run=dry_run,
            use_content=use_content,
            skip_hidden=skip_hidden
        )
        logging.info("File organization completed successfully.")
    except KeyboardInterrupt:
        logging.warning("File organization interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()