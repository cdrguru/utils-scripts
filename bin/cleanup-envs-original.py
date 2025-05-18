#!/usr/bin/env python3
import os
import shutil
import argparse
import sys
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Standard names for virtual environments and Node.js modules
VENV_NAMES = {'.venv', 'venv', 'env'}
NODE_NAMES = {'node_modules'}

# Logging configuration
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

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

    Args:
        paths_to_delete: A list of Path objects to delete.

    Returns:
        A tuple containing two lists: 
        1. Paths of directories successfully deleted.
        2. Paths of directories that failed to delete.
    """
    deleted_successfully = []
    failed_to_delete = []
    
    # Determine number of workers, fallback to 4 if os.cpu_count() is None or 0
    num_workers = os.cpu_count()
    if not num_workers or num_workers < 1:
        num_workers = 4 
    logging.info(f"Starting parallel deletion with up to {num_workers} workers.")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Create a dictionary mapping futures to paths for easy lookup
        future_to_path = {executor.submit(shutil.rmtree, p): p for p in paths_to_delete}
        
        for future in as_completed(future_to_path):
            path_obj = future_to_path[future]
            try:
                future.result() # Raises an exception if the call failed
                logging.info(f"Successfully deleted: {path_obj}")
                deleted_successfully.append(path_obj)
            except PermissionError:
                logging.error(f"Permission denied (cannot delete): {path_obj}")
                failed_to_delete.append(path_obj)
            except FileNotFoundError:
                logging.warning(f"Not found (already deleted or moved?): {path_obj}")
                # Still consider it a "failure" for this script's attempt
                failed_to_delete.append(path_obj)
            except OSError as e:
                logging.error(f"OS error deleting {path_obj}: {e}")
                failed_to_delete.append(path_obj)
            except Exception as e:
                logging.error(f"Unexpected error deleting {path_obj}: {e}")
                failed_to_delete.append(path_obj)
                
    return deleted_successfully, failed_to_delete

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(
        description="Scan for and delete virtual environment directories (e.g., .venv, venv, env) "
                    "and optionally node_modules directories. Supports include/exclude patterns, "
                    "parallel deletion, structured logging, and disk space measurement. Use with caution.",
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
    log_handlers = [logging.StreamHandler(sys.stdout)] # Log to console
    if args.log_file:
        try:
            # Ensure log directory exists if specified as part of path
            args.log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(args.log_file, encoding='utf-8')
            log_handlers.append(file_handler)
        except Exception as e:
            # Fallback to console logging if file handler fails
            logging.basicConfig(level=log_level, format=LOG_FORMAT, handlers=[logging.StreamHandler(sys.stdout)])
            logging.error(f"Could not configure log file at '{args.log_file}': {e}. Logging to console only.")
        else: # If file handler setup is successful
             logging.basicConfig(level=log_level, format=LOG_FORMAT, handlers=log_handlers)
    else: # No log file specified
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

    # Determine the set of names to search for
    active_search_names = set(VENV_NAMES)
    if args.include_node:
        active_search_names.update(NODE_NAMES)
    logging.info(f"Target directory names for initial scan: {active_search_names}")
    
    paths_to_action = find_matching_dirs(scan_root, active_search_names, args.match_exact_only)
    logging.info(f"Initial scan found {len(paths_to_action)} potential director{'y' if len(paths_to_action) == 1 else 'ies'}.")

    # Apply include/exclude patterns
    if args.include or args.exclude:
        logging.info("Applying include/exclude glob patterns...")
        original_path_count = len(paths_to_action)
        
        if args.include:
            paths_after_include = []
            for p in paths_to_action:
                if any(p.match(pattern) for pattern in args.include):
                    paths_after_include.append(p)
                else:
                    logging.debug(f"Path '{p}' did not match any --include patterns.")
            paths_to_action = paths_after_include
            logging.debug(f"{len(paths_to_action)} paths remaining after --include filters.")

        if args.exclude:
            paths_after_exclude = []
            for p in paths_to_action:
                if not any(p.match(pattern) for pattern in args.exclude):
                    paths_after_exclude.append(p)
                else:
                    logging.debug(f"Path '{p}' matched an --exclude pattern.")
            paths_to_action = paths_after_exclude
            logging.debug(f"{len(paths_to_action)} paths remaining after --exclude filters.")

        filtered_out_count = original_path_count - len(paths_to_action)
        if filtered_out_count > 0:
            logging.info(f"Filtered out {filtered_out_count} director{'y' if filtered_out_count == 1 else 'ies'} "
                         f"based on include/exclude patterns.")
    
    if not paths_to_action:
        logging.info("No matching directories found after applying all filters.")
        sys.exit(0)

    sorted_paths = sorted(paths_to_action)

    logging.info(f"Found {len(sorted_paths)} director{'y' if len(sorted_paths) == 1 else 'ies'} to process after filtering:")
    for p in sorted_paths:
        logging.info(f"  - {p}")

    # Handle dry run
    if args.dry_run:
        logging.info("\nDry run complete. No directories will be deleted.")
        if args.measure_space:
            logging.info("Calculating potential space to be freed (this may take a moment)...")
            total_potential_size = 0
            # Calculate sizes sequentially for dry run to avoid overwhelming with threads
            # if many small directories are found. Can be parallelized if performance is an issue.
            for p in sorted_paths:
                dir_size = get_dir_size(p)
                logging.debug(f"Size of '{p}': {human_readable_size(dir_size)}")
                total_potential_size += dir_size
            logging.info(f"Potential disk space to be freed: {human_readable_size(total_potential_size)}")
        sys.exit(0)

    # Confirmation prompt before deletion
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
            logging.error("\nConfirmation prompt skipped due to non-interactive mode (EOFError). "
                          "No directories were deleted. Use --yes (or -y) to confirm deletion "
                          "in non-interactive environments.")
            sys.exit(1)
        except KeyboardInterrupt:
            logging.info("\nOperation aborted by user (Ctrl+C). No directories were deleted.")
            sys.exit(1)

    # Pre-calculate sizes if --measure-space is enabled
    path_sizes = {}
    if args.measure_space:
        logging.info("\nCalculating disk space of target directories (this may take a moment)...")
        # Using a ThreadPoolExecutor to speed up size calculation for multiple directories
        num_workers_size = os.cpu_count()
        if not num_workers_size or num_workers_size < 1:
            num_workers_size = 4
        
        with ThreadPoolExecutor(max_workers=num_workers_size) as executor:
            future_to_path_size = {executor.submit(get_dir_size, p): p for p in sorted_paths}
            for future in as_completed(future_to_path_size):
                p = future_to_path_size[future]
                try:
                    size = future.result()
                    path_sizes[p] = size
                    logging.debug(f"Measured size of '{p}': {human_readable_size(size)}")
                except Exception as e:
                    logging.warning(f"Could not measure size for '{p}': {e}")
                    path_sizes[p] = 0 # Assume 0 if measurement fails
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
        for p_fail in sorted(failed_to_delete): # Sort failed paths for consistent reporting
            logging.error(f"  - {p_fail}")
        # Exit with a non-zero status code if any deletions failed
        sys.exit(1) 
    
    if not deleted_successfully and not failed_to_delete and paths_to_action:
        # This case should ideally not be reached if paths_to_action was populated
        # and deletion was attempted, but it's a safeguard.
        logging.warning("No directories were ultimately processed for deletion, though some were found and targeted.")
    
    logging.info("Cleanup process finished.")
    sys.exit(0)

if __name__ == "__main__":
    main()
