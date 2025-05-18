#!/usr/bin/env python3
import os
import shutil
import argparse
import sys
import logging
import subprocess # Added for fallback deletion
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Standard names for virtual environments and Node.js modules
VENV_NAMES = {'.venv', 'venv', 'env'}
NODE_NAMES = {'node_modules'}

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

def _rmtree_onerror_handler(func_to_retry, path_str_failed: str, exc_info_tuple):
    """
    Error handler for shutil.rmtree, called when an operation within rmtree fails.
    Attempts to change file permissions to writable (0o700 for owner) and 
    retries the failed removal operation (e.g., os.remove, os.rmdir).
    Based on the user-provided strategy.

    Args:
        func_to_retry: The function that raised the exception (e.g., os.remove, os.rmdir).
        path_str_failed: The string representation of the path that caused the error.
        exc_info_tuple: Exception information from sys.exc_info().
    """
    exception_type, exception_value, _ = exc_info_tuple
    logging.warning(
        f"Error during rmtree operation '{func_to_retry.__name__}' on path '{path_str_failed}': {exception_value}. "
        "Attempting to change permissions to 0o700 and retry."
    )
    try:
        # Change permissions to owner rwx (read, write, execute)
        os.chmod(path_str_failed, 0o700)
        logging.debug(f"Changed permissions for '{path_str_failed}' to 0o700.")
        # Retry the original function that failed (e.g., os.remove, os.rmdir)
        func_to_retry(path_str_failed)
        logging.debug(f"Retry of '{func_to_retry.__name__}' on '{path_str_failed}' successful after chmod.")
    except Exception as e:
        # If chmod or the retried func fails, this exception will be caught.
        # It's important to re-raise so that shutil.rmtree knows the error wasn't fully handled
        # by this onerror callback, and the original rmtree call will then raise an exception.
        logging.error(
            f"Error handler failed for '{path_str_failed}' during chmod or retry: {e}. "
            f"Original error was: {exception_value}"
        )
        raise # Re-raise the exception to propagate it from shutil.rmtree

def get_dir_size(path: Path) -> int:
    """
    Recursively calculates the total size of all files within a directory.

    Args:
        path: The Path object of the directory.

    Returns:
        Total size in bytes. Returns 0 if the path is not a directory or is inaccessible.
    """
    total_size = 0
    if not path.is_dir(): # Ensure it's a directory before walking
        logging.debug(f"Cannot calculate size: '{path}' is not a directory or is inaccessible.")
        return 0
        
    try:
        for root, _, files in os.walk(path):
            for fname in files:
                try:
                    file_path = Path(root) / fname
                    # Ensure it's a file and not a symlink to avoid double counting or errors
                    if file_path.is_file() and not file_path.is_symlink():
                        total_size += file_path.stat().st_size
                except FileNotFoundError:
                    logging.debug(f"File not found during size calculation: {file_path}")
                except PermissionError:
                    logging.debug(f"Permission denied for file during size calculation: {file_path}")
                except OSError as e: # Catch other OS-level errors like broken symlinks
                    logging.debug(f"OS error accessing file {file_path} during size calculation: {e}")
    except PermissionError:
        logging.warning(f"Permission denied to walk directory for size calculation: {path}")
    except Exception as e:
        logging.warning(f"Could not calculate size for {path}: {e}")
    return total_size

def human_readable_size(num_bytes: int, suffix='B') -> str:
    """
    Converts a size in bytes to a human-readable string (e.g., 1.2 GiB).

    Args:
        num_bytes: Size in bytes.
        suffix: The suffix to append (default is 'B' for Bytes).

    Returns:
        A human-readable string representation of the size.
    """
    if num_bytes < 0: # Should not happen for directory sizes
        return "N/A"
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}{suffix}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} Yi{suffix}" # YiB for Yottabytes

def find_matching_dirs(root: Path, names_to_scan: set[str], exact_match_only: bool) -> list[Path]:
    """
    Finds directories matching specified names under the root path.
    This function identifies potential candidates; further filtering (e.g., include/exclude)
    is applied later.

    Args:
        root: The directory Path object to start scanning from.
        names_to_scan: A set of directory names (strings) to search for.
        exact_match_only: 
            If True: Only exact, case-sensitive matches for names in `names_to_scan` 
                     are considered (e.g., 'venv' matches 'venv' but not 'my-venv' or 'VENV').
            If False: Matching is broader and includes:
                      1. Exact case-sensitive matches (e.g., '.venv').
                      2. Case-insensitive substring matches (e.g., 'venv' (from names_to_scan,
                         lowercased) in 'my-VENV-project' (also lowercased)).
                         WARNING: This substring match can be greedy. For example, if 'venv'
                         is a name to scan, a directory named 'subvention_project' might also
                         be matched because 'venv' is a substring of 'subvention'.
                         If this behavior is too broad for your needs, use the 
                         --match-exact-only flag when running the script.

    Returns:
        A list of Path objects representing the found directories.
    """
    found_paths = []
    logging.debug(f"Starting directory scan in {root} for names: {names_to_scan} (exact_match_only: {exact_match_only})")
    # os.walk allows us to traverse the directory tree
    for dirpath_str, dirs, _ in os.walk(root, topdown=True):
        current_path = Path(dirpath_str)
        for dir_name in list(dirs): # Iterate over a copy as we modify `dirs`
            is_match = False
            if exact_match_only:
                if dir_name in names_to_scan:
                    is_match = True
            else:
                if dir_name in names_to_scan: # Exact case-sensitive first
                    is_match = True
                else: # Case-insensitive substring match
                    dir_name_lower = dir_name.lower()
                    if any(target_name.lower() in dir_name_lower for target_name in names_to_scan):
                        is_match = True
            
            if is_match:
                matched_path = current_path / dir_name
                logging.debug(f"Found potential match: {matched_path}")
                found_paths.append(matched_path)
                # Prune search: don't recurse into matched directories
                dirs.remove(dir_name)
                
    return found_paths

def delete_paths_parallel(paths_to_delete: list[Path]) -> tuple[list[Path], list[Path]]:
    """
    Deletes a list of directory paths in parallel using shutil.rmtree.
    Includes an onerror handler to attempt to fix permissions and a fallback to 'rm -rf'.

    Args:
        paths_to_delete: A list of Path objects to delete.

    Returns:
        A tuple containing two lists: 
        1. Paths of directories successfully deleted.
        2. Paths of directories that failed to delete.
    """
    deleted_successfully = []
    failed_to_delete = []
    
    num_workers = os.cpu_count()
    if not num_workers or num_workers < 1:
        num_workers = 4 
    logging.info(f"Starting parallel deletion with up to {num_workers} workers.")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_path = {
            executor.submit(shutil.rmtree, p, onerror=_rmtree_onerror_handler): p 
            for p in paths_to_delete
        }
        
        for future in as_completed(future_to_path):
            path_obj = future_to_path[future]
            deleted_this_path_successfully = False
            try:
                future.result() # This will raise if rmtree (with onerror handler) ultimately fails
                logging.info(f"Successfully deleted: {path_obj} (via shutil.rmtree with onerror handler)")
                deleted_successfully.append(path_obj)
                deleted_this_path_successfully = True
            except Exception as e: 
                logging.error(f"shutil.rmtree failed for {path_obj} (even with onerror handler): {e}")
                logging.info(f"Attempting fallback deletion for {path_obj} using 'rm -rf'")
                try:
                    # Using subprocess.call as per user guidance for the fallback
                    return_code = subprocess.call(["rm", "-rf", str(path_obj)])
                    if return_code == 0:
                        logging.info(f"Fallback deletion successful for {path_obj} using 'rm -rf'.")
                        deleted_successfully.append(path_obj)
                        deleted_this_path_successfully = True
                    else:
                        logging.error(f"Fallback 'rm -rf \"{str(path_obj)}\"' failed with return code: {return_code}.")
                except Exception as sub_e:
                    logging.error(f"Exception occurred during fallback 'rm -rf \"{str(path_obj)}\"': {sub_e}")
            
            if not deleted_this_path_successfully:
                failed_to_delete.append(path_obj)
                
    return deleted_successfully, failed_to_delete

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description="Scan for and delete virtual environment directories (e.g., .venv, venv, env) "
                    "and optionally node_modules directories. Supports include/exclude patterns, "
                    "parallel deletion, structured logging, disk space measurement, and robust deletion. Use with caution.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-r', '--root',
        type=Path,
        default=Path.home(),
        help="Directory to scan (default: your home directory)."
    )
    parser.add_argument(
        '--include-node',
        action='store_true',
        help="Also find and delete 'node_modules' directories."
    )
    parser.add_argument(
        '-n', '--dry-run',
        action='store_true',
        help="List directories that would be deleted, but do not delete anything."
    )
    parser.add_argument(
        '-y', '--yes', '--assume-yes',
        action='store_true',
        help="Automatically answer 'yes' to the deletion confirmation prompt. "
             "USE WITH EXTREME CAUTION, as this can lead to data loss."
    )
    parser.add_argument(
        '--match-exact-only',
        action='store_true',
        help="Only match directory names exactly (case-sensitive) during the initial scan. "
             "For example, if 'venv' is a target, this matches 'venv' but NOT 'my-venv'. "
             "This disables the default broader substring matching for initial discovery."
    )
    parser.add_argument(
        '--include',
        action='append',
        default=[],
        metavar='GLOB_PATTERN',
        help="Glob pattern(s) for paths to include. If specified, only paths matching "
             "at least one include pattern are considered (before excludes). "
             "Can be used multiple times (e.g., --include '*src*' --include '*/tests/*')."
    )
    parser.add_argument(
        '--exclude',
        action='append',
        default=[],
        metavar='GLOB_PATTERN',
        help="Glob pattern(s) for paths to exclude. Paths matching any exclude pattern "
             "will be skipped. Can be used multiple times (e.g., --exclude '*.git/*' --exclude '*/important_project/*')."
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable DEBUG level logging to the console."
    )
    parser.add_argument(
        '-l', '--log-file',
        type=Path,
        help="Path to a file where logs will be written (INFO level and above, or DEBUG if -v is also used)."
    )
    parser.add_argument(
        '--measure-space',
        action='store_true',
        help="Calculate and report total disk space that will be (or was) freed. "
             "This can add overhead for very large numbers of directories or deep directory structures."
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_handlers = [logging.StreamHandler(sys.stdout)] 
    if args.log_file:
        try:
            args.log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(args.log_file, encoding='utf-8')
            log_handlers.append(file_handler)
            logging.basicConfig(level=log_level, format=LOG_FORMAT, handlers=log_handlers)
        except Exception as e:
            logging.basicConfig(level=log_level, format=LOG_FORMAT, handlers=[logging.StreamHandler(sys.stdout)]) # Fallback
            logging.error(f"Could not configure log file at '{args.log_file}': {e}. Logging to console only.")
    else: 
        logging.basicConfig(level=log_level, format=LOG_FORMAT, handlers=log_handlers)

    # Validate and resolve the root path
    try:
        scan_root = args.root.expanduser().resolve(strict=True)
        if not scan_root.is_dir():
            logging.error(f"Root path '{scan_root}' is not a directory.")
            sys.exit(1)
    except FileNotFoundError:
        logging.error(f"Root path '{args.root}' does not exist or is not accessible.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error resolving root path '{args.root}': {e}")
        sys.exit(1)

    logging.info(f"Starting scan for target directories under '{scan_root}'.")
    logging.debug(f"Script arguments: {args}")

    active_search_names = set(VENV_NAMES)
    if args.include_node:
        active_search_names.update(NODE_NAMES)
    logging.info(f"Target directory names for initial scan: {active_search_names}")
    
    paths_to_action = find_matching_dirs(scan_root, active_search_names, args.match_exact_only)
    logging.info(f"Initial scan found {len(paths_to_action)} potential director{'y' if len(paths_to_action) == 1 else 'ies'}.")

    if args.include or args.exclude:
        logging.info("Applying include/exclude glob patterns...")
        original_path_count = len(paths_to_action)
        if args.include:
            paths_to_action = [p for p in paths_to_action if any(p.match(pattern) for pattern in args.include)]
            logging.debug(f"{len(paths_to_action)} paths remaining after --include filters.")
        if args.exclude:
            paths_to_action = [p for p in paths_to_action if not any(p.match(pattern) for pattern in args.exclude)]
            logging.debug(f"{len(paths_to_action)} paths remaining after --exclude filters.")
        filtered_out_count = original_path_count - len(paths_to_action)
        if filtered_out_count > 0:
            logging.info(f"Filtered out {filtered_out_count} director{'y' if filtered_out_count == 1 else 'ies'} based on include/exclude patterns.")
    
    if not paths_to_action:
        logging.info("No matching directories found after applying all filters.")
        sys.exit(0)

    sorted_paths = sorted(paths_to_action)
    logging.info(f"Found {len(sorted_paths)} director{'y' if len(sorted_paths) == 1 else 'ies'} to process after filtering:")
    for p in sorted_paths:
        logging.info(f"  - {p}")

    if args.dry_run:
        logging.info("\nDry run complete. No directories will be deleted.")
        if args.measure_space:
            logging.info("Calculating potential space to be freed (this may take a moment)...")
            total_potential_size = sum(get_dir_size(p) for p in sorted_paths)
            logging.info(f"Potential disk space to be freed: {human_readable_size(total_potential_size)}")
        sys.exit(0)

    if not args.yes:
        try:
            prompt_message = "\nProceed with deletion of the directories listed above?"
            if args.measure_space:
                prompt_message += " (Disk space measurement is enabled and will occur before deletion)"
            prompt_message += " (yes/no): "
            response = input(prompt_message).strip().lower()
            if response not in ['yes', 'y']:
                logging.info("Aborted by user. No directories were deleted.")
                sys.exit(0)
        except EOFError: 
            logging.error("\nConfirmation prompt skipped (EOFError). No directories deleted. Use --yes for non-interactive environments.")
            sys.exit(1)
        except KeyboardInterrupt:
            logging.info("\nOperation aborted by user (Ctrl+C). No directories were deleted.")
            sys.exit(1)

    path_sizes = {}
    if args.measure_space:
        logging.info("\nCalculating disk space of target directories (this may take a moment)...")
        num_workers_size = os.cpu_count(); num_workers_size = 4 if not num_workers_size or num_workers_size < 1 else num_workers_size
        with ThreadPoolExecutor(max_workers=num_workers_size) as executor:
            future_to_path_size = {executor.submit(get_dir_size, p): p for p in sorted_paths}
            for future in as_completed(future_to_path_size):
                p, size = future_to_path_size[future], 0
                try:
                    size = future.result()
                    path_sizes[p] = size
                    logging.debug(f"Measured size of '{p}': {human_readable_size(size)}")
                except Exception as e:
                    logging.warning(f"Could not measure size for '{p}': {e}. Assuming 0 bytes.")
                    path_sizes[p] = 0
        logging.info("Disk space measurement complete.")

    logging.info("\nStarting deletion process...")
    deleted_successfully, failed_to_delete = delete_paths_parallel(sorted_paths)

    logging.info("\n--- Deletion Summary ---")
    if deleted_successfully:
        if args.measure_space:
            total_freed_space = sum(path_sizes.get(p, 0) for p in deleted_successfully)
            logging.info(f"Successfully deleted {len(deleted_successfully)} director{'y' if len(deleted_successfully) == 1 else 'ies'} "
                         f"and freed approximately {human_readable_size(total_freed_space)}.")
        else:
            logging.info(f"Successfully deleted {len(deleted_successfully)} director{'y' if len(deleted_successfully) == 1 else 'ies'}.")
    
    if failed_to_delete:
        logging.error(f"Failed to delete {len(failed_to_delete)} director{'y' if len(failed_to_delete) == 1 else 'ies'}:")
        for p_fail in sorted(failed_to_delete):
            logging.error(f"  - {p_fail}")
        sys.exit(1) 
    
    if not deleted_successfully and not failed_to_delete and paths_to_action:
        logging.warning("No directories were ultimately processed for deletion, though some were found and targeted.")
    
    logging.info("Cleanup process finished.")
    sys.exit(0)

if __name__ == "__main__":
    main()
