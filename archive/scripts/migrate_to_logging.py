#!/usr/bin/env python
"""
Automated Print to Logging Migration Script
============================================
Migrates print() statements to proper logging calls.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

def detect_log_level(line: str) -> str:
    """Detect appropriate logging level from print content"""
    line_lower = line.lower()

    # Error patterns
    if any(pattern in line_lower for pattern in ['error', '❌', '✗', 'failed', 'failure', 'exception']):
        return 'error'

    # Warning patterns
    if any(pattern in line_lower for pattern in ['warning', '⚠', 'warn', 'caution']):
        return 'warning'

    # Debug patterns
    if any(pattern in line_lower for pattern in ['debug', 'trace', 'verbose']):
        return 'debug'

    # Info patterns (default)
    return 'info'

def migrate_file(file_path: Path) -> Tuple[int, int]:
    """
    Migrate print() statements to logging in a single file.
    Returns: (original_count, migrated_count)
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Count original prints
    original_count = len(re.findall(r'print\(', content))

    if original_count == 0:
        return 0, 0

    # Check if logging already imported
    has_logging = 'import logging' in content
    has_logger = 'logger = logging.getLogger' in content

    lines = content.split('\n')
    new_lines = []
    imports_section_ended = False
    added_logging = False

    for i, line in enumerate(lines):
        # Add logging import after other imports
        if not added_logging and not has_logging and line.strip() and not line.startswith('#') and not line.startswith('"""') and not line.startswith("'''"):
            if line.startswith('import ') or line.startswith('from '):
                if i + 1 < len(lines) and not (lines[i+1].startswith('import ') or lines[i+1].startswith('from ')):
                    new_lines.append(line)
                    new_lines.append('import logging')
                    new_lines.append('')
                    new_lines.append('# Setup logging')
                    new_lines.append('logger = logging.getLogger(__name__)')
                    new_lines.append('')
                    added_logging = True
                    continue

        # Replace print statements
        if 'print(' in line:
            # Detect indentation
            indent = len(line) - len(line.lstrip())
            indent_str = ' ' * indent

            # Detect log level
            log_level = detect_log_level(line)

            # Replace print( with logger.level(
            new_line = re.sub(r'print\(', f'logger.{log_level}(', line)
            new_lines.append(new_line)
        else:
            new_lines.append(line)

    # If we never added logging (no imports found), add at top
    if not added_logging and not has_logging and original_count > 0:
        insert_pos = 0
        # Skip shebang and docstring
        for i, line in enumerate(new_lines):
            if line.strip() and not line.startswith('#!') and not line.strip().startswith('"""') and not line.strip().startswith("'''"):
                insert_pos = i
                break

        new_lines.insert(insert_pos, 'import logging')
        new_lines.insert(insert_pos + 1, '')
        new_lines.insert(insert_pos + 2, '# Setup logging')
        new_lines.insert(insert_pos + 3, 'logger = logging.getLogger(__name__)')
        new_lines.insert(insert_pos + 4, '')

    new_content = '\n'.join(new_lines)

    # Count migrated prints (should be 0)
    migrated_count = original_count - len(re.findall(r'print\(', new_content))

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    return original_count, migrated_count

def main():
    """Migrate all Python files in scripts directory"""
    scripts_dir = Path(__file__).parent

    # Files to skip (already migrated or special cases)
    skip_files = {
        'create_video_auto.py',  # Already migrated
        'translation_service.py',  # Already migrated
        'generate_videos_from_timings_unified.py',  # Already migrated
        'generate_documentation_videos.py',  # Already migrated
        'migrate_to_logging.py',  # This script
    }

    python_files = [f for f in scripts_dir.glob('*.py') if f.name not in skip_files]

    print(f"\nMigrating {len(python_files)} Python files to logging...")
    print("=" * 70)

    total_original = 0
    total_migrated = 0
    results = []

    for py_file in sorted(python_files):
        orig, migr = migrate_file(py_file)
        if orig > 0:
            total_original += orig
            total_migrated += migr
            results.append((py_file.name, orig, migr))
            status = "✓" if migr == orig else "⚠"
            print(f"{status} {py_file.name}: {orig} prints → {migr} migrated")

    print("=" * 70)
    print(f"\nSummary:")
    print(f"  Files processed: {len(results)}")
    print(f"  Total print statements: {total_original}")
    print(f"  Successfully migrated: {total_migrated}")
    print(f"  Migration rate: {(total_migrated/total_original*100) if total_original > 0 else 0:.1f}%")

    if total_migrated < total_original:
        print(f"\n⚠ Warning: {total_original - total_migrated} prints may need manual review")

if __name__ == '__main__':
    main()
