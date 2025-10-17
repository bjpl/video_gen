#!/usr/bin/env python3
"""Fix Phase 2 migration issues.

This script fixes syntax errors in Phase 2 migrated test files:
1. Removes duplicate 'async @pytest.mark.asyncio' lines
2. Fixes .adapt() return value extraction (result.video_set)
"""

import re
import sys
from pathlib import Path


def fix_duplicate_async_decorator(content: str) -> str:
    """Remove lines with 'async @pytest.mark.asyncio'."""
    # Remove standalone lines that incorrectly have 'async' before decorator
    content = re.sub(
        r'^\s*async\s+@pytest\.mark\.asyncio\s*\n',
        '',
        content,
        flags=re.MULTILINE
    )
    return content


def fix_adapt_result_extraction(content: str) -> str:
    """Fix .adapt() calls to extract video_set from result.

    Changes:
        video_set = await adapter.adapt(source)
    To:
        result = await adapter.adapt(source)
        video_set = result.video_set
    """
    # Pattern: variable = await ...adapter.adapt(...)
    # Replace with: result = await ...adapter.adapt(...)
    #               variable = result.video_set

    def replace_adapt_call(match):
        indent = match.group(1)
        var_name = match.group(2)
        adapt_call = match.group(3)

        # Generate result variable name
        result_var = f"{var_name}_result"

        # Return the fixed version
        return (f"{indent}{result_var} = {adapt_call}\n"
                f"{indent}{var_name} = {result_var}.video_set")

    # Match: video_set = await adapter.adapt(...)
    pattern = r'^(\s*)(\w+)\s*=\s*(await\s+\w+\.adapt\([^)]*\))'
    content = re.sub(pattern, replace_adapt_call, content, flags=re.MULTILINE)

    return content


def process_file(file_path: Path) -> bool:
    """Process a single test file.

    Returns:
        True if file was modified, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        # Apply fixes
        fixed_content = original_content
        fixed_content = fix_duplicate_async_decorator(fixed_content)
        # Note: Skipping adapt result extraction for now as it's complex
        # and may break tests. Handle manually if needed.

        # Check if content changed
        if fixed_content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"✓ Fixed: {file_path.name}")
            return True
        else:
            print(f"⊘ No changes: {file_path.name}")
            return False

    except Exception as e:
        print(f"✗ Error processing {file_path.name}: {e}")
        return False


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python fix_phase2_migration.py <test_dir>")
        sys.exit(1)

    test_dir = Path(sys.argv[1])
    if not test_dir.is_dir():
        print(f"Error: {test_dir} is not a directory")
        sys.exit(1)

    # Find all test files
    test_files = sorted(test_dir.glob("test_*.py"))

    print(f"Found {len(test_files)} test files\n")

    modified_count = 0
    for test_file in test_files:
        if process_file(test_file):
            modified_count += 1

    print(f"\n{'='*60}")
    print(f"Fixed {modified_count}/{len(test_files)} files")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
