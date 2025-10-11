#!/usr/bin/env python3
"""
Automated Test Migration Script for Input Adapter Consolidation
================================================================

Migrates test files from deprecated app.input_adapters to canonical
video_gen.input_adapters.compat layer.

Usage:
    # Dry run (show what would change)
    python scripts/migrate_adapter_imports.py --dry-run

    # Migrate specific files
    python scripts/migrate_adapter_imports.py tests/test_input_adapters.py

    # Migrate all test files
    python scripts/migrate_adapter_imports.py --all

    # Migrate with backup
    python scripts/migrate_adapter_imports.py --all --backup

Features:
    - Automatically detects deprecated imports
    - Preserves code formatting and comments
    - Creates backups before modification
    - Generates migration report
    - Validates imports post-migration
"""

import re
import sys
import argparse
from pathlib import Path
from typing import List, Tuple, Set
import shutil


# Import patterns to replace
DEPRECATED_PATTERNS = [
    # Pattern 1: from app.input_adapters import X
    (
        r'from app\.input_adapters import (.+)',
        r'from video_gen.input_adapters.compat import \1'
    ),
    # Pattern 2: from app.input_adapters.module import X
    (
        r'from app\.input_adapters\.(\w+) import (.+)',
        r'from video_gen.input_adapters.compat import \2  # Migrated from app.input_adapters.\1'
    ),
    # Pattern 3: import app.input_adapters.module as alias (FIXED)
    (
        r'import app\.input_adapters\.(\w+) as (\w+)',
        r'from video_gen.input_adapters import compat as \2  # Note: was app.input_adapters.\1'
    ),
    # Pattern 4: import app.input_adapters (generic)
    (
        r'import app\.input_adapters(?!\.)',  # Negative lookahead to not match .module
        r'from video_gen.input_adapters import compat as input_adapters'
    ),
]


class MigrationStats:
    """Track migration statistics"""

    def __init__(self):
        self.files_processed = 0
        self.files_modified = 0
        self.imports_replaced = 0
        self.errors: List[Tuple[Path, str]] = []

    def report(self) -> str:
        """Generate migration report"""
        report = []
        report.append("=" * 60)
        report.append("MIGRATION REPORT")
        report.append("=" * 60)
        report.append(f"Files processed: {self.files_processed}")
        report.append(f"Files modified:  {self.files_modified}")
        report.append(f"Imports replaced: {self.imports_replaced}")

        if self.errors:
            report.append(f"\nErrors: {len(self.errors)}")
            for file_path, error in self.errors:
                report.append(f"  - {file_path}: {error}")
        else:
            report.append("\n✅ Migration completed successfully!")

        report.append("=" * 60)
        return "\n".join(report)


def find_deprecated_imports(file_path: Path) -> Set[str]:
    """Find all deprecated import lines in a file"""
    content = file_path.read_text()
    imports = set()

    for pattern, _ in DEPRECATED_PATTERNS:
        # Find full lines containing the pattern
        lines = content.split('\n')
        for line in lines:
            if re.search(pattern, line):
                imports.add(line.strip())

    return imports


def migrate_file(file_path: Path, dry_run: bool = False, backup: bool = True) -> Tuple[int, bool]:
    """
    Migrate a single file from deprecated to canonical imports.

    Returns:
        Tuple of (replacements_made, file_was_modified)
    """
    try:
        content = file_path.read_text()
        original_content = content
        replacements = 0

        # Apply each pattern
        for pattern, replacement in DEPRECATED_PATTERNS:
            new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
            if new_content != content:
                count = len(re.findall(pattern, content, re.MULTILINE))
                replacements += count
                content = new_content

        if content == original_content:
            return 0, False  # No changes needed

        if dry_run:
            print(f"\n{'='*60}")
            print(f"Would modify: {file_path}")
            print(f"{'='*60}")
            print("\nDeprecated imports found:")
            imports = find_deprecated_imports(file_path)
            for imp in sorted(imports):
                print(f"  - {imp}")
            print(f"\nTotal replacements: {replacements}")
            return replacements, True

        # Create backup if requested
        if backup:
            backup_path = file_path.with_suffix(file_path.suffix + '.backup')
            shutil.copy2(file_path, backup_path)
            print(f"  📦 Backup created: {backup_path}")

        # Write migrated content
        file_path.write_text(content)
        print(f"  ✅ Migrated: {file_path} ({replacements} replacements)")

        return replacements, True

    except Exception as e:
        raise RuntimeError(f"Error migrating {file_path}: {e}")


def validate_migration(file_path: Path) -> bool:
    """Validate that migration was successful"""
    content = file_path.read_text()

    # Check for remaining deprecated imports
    for pattern, _ in DEPRECATED_PATTERNS:
        if re.search(pattern, content):
            return False

    # Check for new canonical imports
    if 'from video_gen.input_adapters.compat import' in content:
        return True

    return True  # No imports changed


def migrate_directory(directory: Path, dry_run: bool = False, backup: bool = True,
                     pattern: str = "test_*.py") -> MigrationStats:
    """Migrate all test files in a directory"""
    stats = MigrationStats()

    test_files = sorted(directory.glob(pattern))
    print(f"\nFound {len(test_files)} test files matching '{pattern}'")

    for file_path in test_files:
        stats.files_processed += 1

        try:
            replacements, modified = migrate_file(file_path, dry_run, backup)

            if modified:
                stats.files_modified += 1
                stats.imports_replaced += replacements

                if not dry_run:
                    # Validate migration
                    if not validate_migration(file_path):
                        stats.errors.append((file_path, "Validation failed - deprecated imports remain"))

        except Exception as e:
            stats.errors.append((file_path, str(e)))

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Migrate test files from deprecated to canonical input adapters"
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Specific files to migrate (or use --all)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Migrate all test files in tests/ directory"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying files"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        default=True,
        help="Create .backup files before modifying (default: True)"
    )
    parser.add_argument(
        "--no-backup",
        action="store_false",
        dest="backup",
        help="Don't create backup files"
    )
    parser.add_argument(
        "--pattern",
        default="test_*.py",
        help="File pattern for --all mode (default: test_*.py)"
    )

    args = parser.parse_args()

    # Determine files to migrate
    if args.all:
        tests_dir = Path("tests")
        if not tests_dir.exists():
            print(f"Error: tests/ directory not found")
            return 1

        stats = migrate_directory(tests_dir, args.dry_run, args.backup, args.pattern)
        print(f"\n{stats.report()}")
        return 0 if not stats.errors else 1

    elif args.files:
        stats = MigrationStats()

        for file_path_str in args.files:
            file_path = Path(file_path_str)

            if not file_path.exists():
                print(f"Error: {file_path} not found")
                continue

            stats.files_processed += 1

            try:
                replacements, modified = migrate_file(file_path, args.dry_run, args.backup)

                if modified:
                    stats.files_modified += 1
                    stats.imports_replaced += replacements

            except Exception as e:
                stats.errors.append((file_path, str(e)))

        print(f"\n{stats.report()}")
        return 0 if not stats.errors else 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
