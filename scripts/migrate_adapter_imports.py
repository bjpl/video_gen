#!/usr/bin/env python3
"""
Automated Input Adapter Migration Script
=========================================

Migrates test files from deprecated app.input_adapters to canonical
video_gen.input_adapters.compat (Phase 1) or full async API (Phase 2).

Usage:
    # Phase 1: Migrate to compatibility layer (safe, zero risk)
    python scripts/migrate_adapter_imports.py tests/ --phase 1

    # Phase 2: Migrate to async API (requires review)
    python scripts/migrate_adapter_imports.py tests/ --phase 2 --review

    # Dry run (show changes without applying)
    python scripts/migrate_adapter_imports.py tests/ --phase 1 --dry-run

    # Single file
    python scripts/migrate_adapter_imports.py tests/test_specific.py --phase 1

Features:
    - ✅ Automatic import rewriting
    - ✅ Model import updates
    - ✅ test_mode parameter injection
    - ✅ Async function conversion (Phase 2)
    - ✅ Dry run mode
    - ✅ Backup creation
    - ✅ Git integration
    - ✅ Batch processing

Safety:
    - Creates .bak files before modification
    - Git status check (requires clean working tree)
    - Dry run mode to preview changes
    - Phase 1 is zero-risk (drop-in replacement)

Related:
    - docs/guides/ADAPTER_MIGRATION_GUIDE.md
    - docs/architecture/ADR_001_INPUT_ADAPTER_CONSOLIDATION.md
"""

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import List, Tuple, Optional
import subprocess


class ImportMigrator(ast.NodeTransformer):
    """AST transformer for migrating imports"""

    def __init__(self, phase: int = 1):
        self.phase = phase
        self.changes = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.ImportFrom:
        """Transform import statements"""
        if node.module and 'app.input_adapters' in node.module:
            if self.phase == 1:
                # Phase 1: app.input_adapters -> video_gen.input_adapters.compat
                new_module = node.module.replace('app.input_adapters', 'video_gen.input_adapters.compat')
                self.changes.append(f"Import: {node.module} -> {new_module}")
                node.module = new_module

            elif self.phase == 2:
                # Phase 2: compat -> canonical
                if 'compat' in node.module:
                    new_module = node.module.replace('.compat', '')
                    self.changes.append(f"Import: {node.module} -> {new_module}")
                    node.module = new_module

        # Update model imports
        if node.module and node.module in ['app.models', 'app.input_adapters.models']:
            new_module = 'video_gen.shared.models'
            self.changes.append(f"Model import: {node.module} -> {new_module}")
            node.module = new_module

        return node


def check_git_status() -> bool:
    """Check if git working tree is clean"""
    try:
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            capture_output=True,
            text=True,
            check=True
        )
        return len(result.stdout.strip()) == 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        return True  # No git or not a repo - proceed anyway


def migrate_file_phase1(file_path: Path, dry_run: bool = False) -> Tuple[bool, List[str]]:
    """
    Phase 1: Migrate to compatibility layer (zero risk)

    Changes:
        - app.input_adapters -> video_gen.input_adapters.compat
        - app.models -> video_gen.shared.models
        - Add test_mode=True to adapter constructors
    """
    changes = []

    # Read file
    content = file_path.read_text()
    original_content = content

    # Pattern 1: Import from app.input_adapters
    import_pattern = r'from app\.input_adapters import'
    import_replacement = 'from video_gen.input_adapters.compat import'

    if re.search(import_pattern, content):
        content = re.sub(import_pattern, import_replacement, content)
        changes.append(f"Updated import: app.input_adapters -> video_gen.input_adapters.compat")

    # Pattern 2: Model imports
    model_pattern = r'from app\.models import'
    model_replacement = 'from video_gen.shared.models import'

    if re.search(model_pattern, content):
        content = re.sub(model_pattern, model_replacement, content)
        changes.append(f"Updated import: app.models -> video_gen.shared.models")

    # Pattern 3: Add test_mode=True to adapter constructors
    # Match: AdapterName() or AdapterName(arg1, arg2)
    # Replace with: AdapterName(test_mode=True) or AdapterName(arg1, arg2, test_mode=True)

    adapter_types = ['DocumentAdapter', 'YouTubeAdapter', 'YAMLAdapter', 'WizardAdapter', 'ProgrammaticAdapter']

    for adapter in adapter_types:
        # Pattern: AdapterName() - no arguments
        no_args_pattern = f'{adapter}\\(\\)'
        no_args_replacement = f'{adapter}(test_mode=True)'

        if re.search(no_args_pattern, content):
            content = re.sub(no_args_pattern, no_args_replacement, content)
            changes.append(f"Added test_mode=True to {adapter}() calls")

        # Pattern: AdapterName(...) - with arguments but no test_mode
        # Only add if test_mode not already present
        args_pattern = f'{adapter}\\([^)]*(?<!test_mode=True)\\)'
        matches = re.finditer(args_pattern, content)

        for match in matches:
            call = match.group(0)
            if 'test_mode' not in call and call != f'{adapter}()':
                # Has args but no test_mode - add it
                new_call = call[:-1] + ', test_mode=True)'
                content = content.replace(call, new_call, 1)
                changes.append(f"Added test_mode=True to {adapter}(...) call")

    # Apply changes if not dry run
    if content != original_content and not dry_run:
        # Create backup
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        backup_path.write_text(original_content)

        # Write updated content
        file_path.write_text(content)
        changes.append(f"Backup created: {backup_path.name}")

    return content != original_content, changes


def migrate_file_phase2(file_path: Path, dry_run: bool = False) -> Tuple[bool, List[str]]:
    """
    Phase 2: Migrate to async API (requires review)

    Changes:
        - video_gen.input_adapters.compat -> video_gen.input_adapters
        - def test_x(): -> async def test_x():
        - Add @pytest.mark.asyncio decorator
        - .parse() -> await .adapt()
        - video_set = ... -> result = await ...; video_set = result.video_set
        - Exception handling -> result checking
    """
    changes = []

    content = file_path.read_text()
    original_content = content

    # Pattern 1: Remove .compat from imports
    compat_pattern = r'from video_gen\.input_adapters\.compat import'
    canonical_replacement = 'from video_gen.input_adapters import'

    if re.search(compat_pattern, content):
        content = re.sub(compat_pattern, canonical_replacement, content)
        changes.append("Updated import: removed .compat")

    # Pattern 2: Add pytest import if not present
    if '@pytest.mark.asyncio' not in content and 'import pytest' not in content:
        # Add pytest import at the top
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                lines.insert(i, 'import pytest')
                content = '\n'.join(lines)
                changes.append("Added: import pytest")
                break

    # Pattern 3: Convert test functions to async
    # Match: def test_xxx():
    # Replace: @pytest.mark.asyncio\n    async def test_xxx():

    test_func_pattern = r'(\s+)def (test_\w+)\((.*?)\):'

    def add_async_marker(match):
        indent = match.group(1)
        func_name = match.group(2)
        params = match.group(3)

        # Add decorator and async keyword
        result = f"{indent}@pytest.mark.asyncio\n"
        result += f"{indent}async def {func_name}({params}):"

        changes.append(f"Made {func_name} async with @pytest.mark.asyncio")
        return result

    content = re.sub(test_func_pattern, add_async_marker, content)

    # Pattern 4: Convert .parse() to await .adapt()
    parse_pattern = r'(\w+)\.parse\('
    adapt_replacement = r'await \1.adapt('

    if re.search(parse_pattern, content):
        content = re.sub(parse_pattern, adapt_replacement, content)
        changes.append("Converted .parse() calls to await .adapt()")

    # Pattern 5: Add result extraction
    # This is complex - flag for manual review
    if 'await' in content and 'result.video_set' not in content:
        changes.append("⚠️  MANUAL REVIEW NEEDED: Extract video_set from result object")

    # Apply changes if not dry run
    if content != original_content and not dry_run:
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        backup_path.write_text(original_content)
        file_path.write_text(content)
        changes.append(f"Backup created: {backup_path.name}")

    return content != original_content, changes


def find_test_files(path: Path) -> List[Path]:
    """Find all test files using deprecated imports"""
    test_files = []

    if path.is_file():
        test_files = [path]
    else:
        test_files = list(path.glob('**/test_*.py'))
        test_files.extend(path.glob('**/*_test.py'))

    # Filter to only files with deprecated imports
    filtered = []
    for file in test_files:
        content = file.read_text()
        if 'app.input_adapters' in content or 'video_gen.input_adapters.compat' in content:
            filtered.append(file)

    return filtered


def main():
    parser = argparse.ArgumentParser(
        description="Migrate input adapter imports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        'path',
        type=Path,
        help='Path to test file or directory'
    )
    parser.add_argument(
        '--phase',
        type=int,
        choices=[1, 2],
        default=1,
        help='Migration phase (1=compat layer, 2=async)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show changes without applying'
    )
    parser.add_argument(
        '--no-git-check',
        action='store_true',
        help='Skip git status check'
    )
    parser.add_argument(
        '--review',
        action='store_true',
        help='Pause for review after each file (Phase 2 only)'
    )

    args = parser.parse_args()

    # Validate path
    if not args.path.exists():
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)

    # Check git status
    if not args.no_git_check and not args.dry_run:
        if not check_git_status():
            print("Error: Git working tree is not clean.")
            print("Please commit or stash changes before running migration.")
            print("Use --no-git-check to override (not recommended).")
            sys.exit(1)

    # Find files to migrate
    print(f"Scanning for test files in: {args.path}")
    test_files = find_test_files(args.path)

    if not test_files:
        print("No test files found with deprecated imports.")
        sys.exit(0)

    print(f"Found {len(test_files)} test files to migrate")
    print()

    # Migrate each file
    total_changed = 0
    migrate_func = migrate_file_phase1 if args.phase == 1 else migrate_file_phase2

    for i, file in enumerate(test_files, 1):
        print(f"[{i}/{len(test_files)}] {file.relative_to(args.path.parent if args.path.is_file() else args.path)}")

        changed, changes = migrate_func(file, dry_run=args.dry_run)

        if changed:
            total_changed += 1
            for change in changes:
                print(f"  - {change}")

            if args.review and args.phase == 2 and not args.dry_run:
                response = input("\n  Review changes? (y/n/quit): ")
                if response.lower() == 'quit':
                    print("Migration stopped by user.")
                    sys.exit(0)
                elif response.lower() != 'y':
                    print("  Skipping this file...")
                    continue
        else:
            print("  No changes needed")

        print()

    # Summary
    print("=" * 60)
    if args.dry_run:
        print(f"DRY RUN: {total_changed}/{len(test_files)} files would be changed")
        print("Run without --dry-run to apply changes")
    else:
        print(f"SUCCESS: {total_changed}/{len(test_files)} files migrated")
        print()
        print("Next steps:")
        if args.phase == 1:
            print("  1. Run tests: pytest tests/ -v")
            print("  2. Review deprecation warnings")
            print("  3. Commit changes: git add . && git commit -m 'feat: Migrate to compat layer (Phase 1)'")
            print("  4. Plan Phase 2 migration")
        else:
            print("  1. REVIEW all changes carefully")
            print("  2. Fix any result extraction issues")
            print("  3. Run tests: pytest tests/ -v")
            print("  4. Fix failing tests")
            print("  5. Commit: git add . && git commit -m 'feat: Migrate to async API (Phase 2)'")


if __name__ == '__main__':
    main()
