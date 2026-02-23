#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import argparse
from pathlib import Path

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
        description="Automate IETF draft release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

1. Dry run to see what version would be created:
   $ ./release_draft.py --dry-run

2. Create a new version from a master 'draft.md' file and commit locally:
   $ ./release_draft.py --source draft.md

3. Create a new version and push to GitHub:
   $ ./release_draft.py --push

4. Force a specific version number (e.g., 00):
   $ ./release_draft.py --version 00

5. Manually specify the draft prefix (if it can't be inferred):
   $ ./release_draft.py --prefix draft-mw-wimse-transitive-attestation
"""
    )
    parser.add_argument("--source", default="draft", help="The non-versioned master .md file to copy from (default: draft).")
    parser.add_argument("--prefix", help="The draft prefix (e.g., draft-mw-wimse-transitive-attestation).")
    parser.add_argument("--version", help="Explicitly set the version number (e.g., 00, 01). Overrides auto-increment.")
    parser.add_argument("--push", action="store_true", help="Push changes to git.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without doing it.")
    
    args = parser.parse_args()
    
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
        next_version_str = args.version
    else:
        current_version = get_latest_version(args.prefix)
        next_version = current_version + 1
        next_version_str = f"{next_version:02d}"
    
    new_filename = f"{args.prefix}-{next_version_str}.md"
    print(f"Target version: {next_version_str} ({new_filename})")

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
    update_metadata(new_filename, next_version_str, args.prefix)

    # 3. Build
    if os.path.exists("Makefile"):
        run_command("make", "running make")
    else:
        print("Warning: Makefile not found, skipping build.")

    # 4. Git operations
    run_command("git add .", "staging changes")
    commit_msg = f"Release version {next_version_str}"
    run_command(f'git commit -m "{commit_msg}"', f"committing release {next_version_str}")
    
    if args.push:
        run_command("git push", "pushing to remote")
        print("Release pushed successfully.")
    else:
        print("Release committed locally (not pushed).")

if __name__ == "__main__":
    main()
