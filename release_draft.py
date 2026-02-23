#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import argparse
from pathlib import Path

# --- Configuration (User can edit these) ---
VERSION = ""    # Set explicitly (e.g., "00") to target a version, or leave empty "" for latest.
SOURCE = "draft" # The default master file to copy from.
AUTO_BUMP = False # Set to True to automatically increment the version on every run.
PUSH = True      # Set to False to commit locally only by default.
# ---------------------------------------------

def get_latest_version(prefix):
    """Finds the latest version number for files starting with the prefix."""
    files = list(Path('.').glob(f"{prefix}-*.md"))
    if not files:
        return -1
    
    versions = []
    for f in files:
        match = re.search(r'-(\d+)\.md$', f.name)
        if match:
            versions.append(int(match.group(1)))
    
    return max(versions) if versions else -1

def update_metadata(file_path, new_version_str, doc_name_base):
    """Updates docName and seriesInfo value in the markdown file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    new_doc_name = f"{doc_name_base}-{new_version_str}"
    
    # Update docName
    content = re.sub(r'docName\s*=\s*"[^"]+"', f'docName = "{new_doc_name}"', content)
    
    # Update seriesInfo value
    content = re.sub(r'value\s*=\s*"[^"]+"', f'value = "{new_doc_name}"', content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    print(f"Updated metadata in {file_path} to version {new_version_str}")

def run_command(command, description):
    """Runs a shell command and handles errors."""
    print(f"Executing: {description}...")
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}:")
        print(e.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Automate IETF draft release (Compile & Push).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

1. Compile 'draft.md', update the current version file, commit, and push:
   $ ./release_draft.py

2. Increment the version (bump), build, commit, and push:
   $ ./release_draft.py --bump

3. Dry run to see what version would be targeted:
   $ ./release_draft.py --dry-run

4. Compile and commit locally, but do not push:
   $ ./release_draft.py --no-push

5. Force a specific version number (e.g., 00):
   $ ./release_draft.py --version 00
"""
    )
    parser.add_argument("--source", default=SOURCE, help=f"The non-versioned master .md file to copy from (default: {SOURCE}).")
    parser.add_argument("--prefix", help="The draft prefix (e.g., draft-mw-wimse-transitive-attestation).")
    parser.add_argument("--version", default=VERSION, help="Explicitly set the version number (e.g., 00, 01). Overrides logic.")
    parser.add_argument("--bump", action="store_true", default=AUTO_BUMP, help=f"Increment the version number (default: {AUTO_BUMP}).")
    parser.add_argument("--no-push", action="store_true", help="Disable automatic git push.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without doing it.")
    
    args = parser.parse_args()
    
    # Logic for push default
    should_push = PUSH and not args.no_push

    if not args.prefix:
        # Try to infer prefix from existing files
        md_files = list(Path('.').glob("draft-*.md"))
        if md_files:
            # Extract common prefix
            prefixes = set()
            for f in md_files:
                match = re.match(r'(draft-.*?)-\d+\.md', f.name)
                if match:
                    prefixes.add(match.group(1))
            if len(prefixes) == 1:
                args.prefix = list(prefixes)[0]
                print(f"Inferred prefix: {args.prefix}")
            else:
                print("Error: Could not infer a single unique prefix. Please specify --prefix.")
                sys.exit(1)
        else:
            print("Error: No versioned .md files found. Please specify --prefix.")
            sys.exit(1)

    if args.version:
        target_version_str = args.version
    else:
        current_version = get_latest_version(args.prefix)
        if current_version < 0:
            target_version = 0
            print("No existing version found. Starting at 00.")
        else:
            target_version = current_version + (1 if args.bump else 0)
        
        target_version_str = f"{target_version:02d}"
    
    new_filename = f"{args.prefix}-{target_version_str}.md"
    print(f"Target version: {target_version_str} ({new_filename})")

    if args.dry_run:
        print("Dry run: Skipping file operations and git commands.")
        return

    # 1. Copy source to versioned file
    source_file = None
    if args.source:
        if os.path.exists(args.source):
            source_file = args.source
        elif not args.source.endswith(".md") and os.path.exists(args.source + ".md"):
            source_file = args.source + ".md"
        else:
            print(f"Error: Source file '{args.source}' not found.")
            sys.exit(1)

    if source_file:
        run_command(f"cp {source_file} {new_filename}", f"copying {source_file} to {new_filename}")
    elif current_version >= 0:
        prev_filename = f"{args.prefix}-{current_version:02d}.md"
        run_command(f"cp {prev_filename} {new_filename}", f"copying previous version {prev_filename} to {new_filename}")
    else:
        print("Error: No source or previous version found.")
        sys.exit(1)

    # 2. Update metadata
    update_metadata(new_filename, target_version_str, args.prefix)

    # 3. Build
    if os.path.exists("Makefile"):
        run_command("make", "running make")
    else:
        print("Warning: Makefile not found, skipping build.")

    # 4. Git operations
    run_command("git add .", "staging changes")
    commit_msg = f"Update version {target_version_str}"
    run_command(f'git commit -m "{commit_msg}"', f"committing update {target_version_str}")
    
    if should_push:
        run_command("git push", "pushing to remote")
        print("Release pushed successfully.")
    else:
        print("Changes committed locally (not pushed).")

if __name__ == "__main__":
    main()
