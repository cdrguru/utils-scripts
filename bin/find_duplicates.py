"""
A utility script to find and manage duplicate files in a directory.
Identifies duplicates based on size, type, and optionally content hash.
"""

import os
import sys
import hashlib
import argparse
import logging
from collections import defaultdict
from typing import List, Optional

# Third-party imports
try:
    import filetype
except ImportError:
    print("Error: Please install filetype package using 'pip install filetype'")
    sys.exit(1)


def configure_logging(log_file: str = "find_duplicates.log") -> None:
    """
    Configures the logging settings.
    Logs are written to both console and a log file.
    
    Args:
        log_file: Path to the log file
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )

def get_file_hash(file_path: str, hash_algo: str = 'sha256') -> Optional[str]:
    """Generates a hash for the given file using the specified hashing algorithm."""
    hash_func = hashlib.new(hash_algo)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as err:
        logging.error("Error hashing file %s: %s", file_path, err)
        return None


def get_correct_extension(file_path: str) -> Optional[str]:
    """Returns the correct file extension based on file content."""
    try:
        kind = filetype.guess(file_path)
        return kind.extension if kind else None
    except Exception as err:
        logging.error("Error getting file extension for %s: %s", file_path, err)
        return None


def find_duplicates(
    directory: str, recursive: bool = False, use_hash: bool = False
) -> List[List[str]]:
    """
    Identifies duplicate files in the specified directory.
    
    Args:
        directory: Path to search for duplicates
        recursive: Whether to search subdirectories
        use_hash: Whether to compare file contents
        
    Returns:
        List of lists containing paths to duplicate files
    """
    duplicates = []
    file_dict = defaultdict(list)

    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)

            if not os.path.isfile(file_path):
                continue

            try:
                file_size = os.path.getsize(file_path)
                file_extension = get_correct_extension(file_path) or "unknown"
                
                key = (file_size, file_extension)
                
                if use_hash:
                    file_hash = get_file_hash(file_path)
                    if file_hash is None:
                        continue
                    key = (*key, file_hash)

                file_dict[key].append(file_path)

            except OSError as err:
                logging.error("Error processing file %s: %s", file_path, err)
                continue

        if not recursive:
            break

    return [files for files in file_dict.values() if len(files) > 1]


def report_duplicates(duplicates: List[List[str]], delete: bool = False) -> None:
    """
    Reports and optionally deletes duplicate files.
    
    Args:
        duplicates: List of duplicate file groups
        delete: Whether to delete duplicate files
    """
    if not duplicates:
        logging.info("No duplicate files found.")
        return

    logging.info("Found %d groups of duplicate files.", len(duplicates))

    for idx, group in enumerate(duplicates, start=1):
        logging.info("\nDuplicate Group %d:", idx)
        for file in group:
            logging.info(" - %s", file)
            
        if delete and len(group) > 1:
            for file_path in group[1:]:
                try:
                    os.remove(file_path)
                    logging.info("Deleted duplicate file: %s", file_path)
                except OSError as err:
                    logging.error(
                        "Error deleting file %s: %s", 
                        file_path, 
                        err
                    )


def main() -> None:
    """
    Main function to parse arguments and find/report duplicates.
    """
    parser = argparse.ArgumentParser(
        description="Identify and optionally delete duplicate files based on size, type, and content."
    )
    parser.add_argument(
        "directory", help="Path to the directory to scan for duplicate files."
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories.",
    )
    parser.add_argument(
        "-c",
        "--check-hash",
        action="store_true",
        help="Use file content hash to confirm duplicates.",
    )
    parser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="Delete duplicate files, keeping one copy per group.",
    )
    parser.add_argument(
        "--log-file",
        default="find_duplicates.log",
        help="Path to the log file (default: find_duplicates.log)",
    )

    args = parser.parse_args()
    directory = args.directory
    recursive = args.recursive
    use_hash = args.check_hash
    delete = args.delete

    configure_logging(args.log_file)
    logging.info(f"Content hash check: {'Enabled' if use_hash else 'Disabled'}")
    logging.info(f"Delete duplicates: {'Enabled' if delete else 'Disabled'}")

    duplicates = find_duplicates(directory, recursive, use_hash)
    report_duplicates(duplicates, delete)

    logging.info("Duplicate scanning completed.")


if __name__ == "__main__":
    main()
