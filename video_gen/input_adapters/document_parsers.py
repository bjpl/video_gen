"""Document parsing functionality for PDF, DOCX, TXT, and Markdown files.

This module handles all document parsing logic, including:
- Markdown structure parsing
- Table extraction
- Code block detection
- List processing (nested)
- Link extraction
"""

import re
from typing import Dict, List, Any


def parse_markdown_structure(content: str) -> Dict[str, Any]:
    """Parse markdown content into structured format.

    Enhanced with support for:
    - Nested lists (up to 3 levels)
    - Tables (basic markdown tables)
    - Better handling of malformed markdown
    - Link extraction
    - Metadata stripping (Generated:, dates, etc.)

    Args:
        content: Raw markdown content

    Returns:
        Structured dict with title, sections, tables
    """
    # Strip common metadata patterns from beginning
    lines = content.split('\n')
    cleaned_lines = []
    skip_metadata = True

    for line in lines:
        # Skip metadata lines at document start
        if skip_metadata:
            # Skip lines like: *Generated: October 05, 2025*
            if re.match(r'^\*?Generated:.*\*?$', line.strip(), re.IGNORECASE):
                continue
            # Skip horizontal rules at start (---, ***, ___)
            if re.match(r'^[\s]*[-*_]{3,}[\s]*$', line.strip()):
                continue
            # Skip empty lines at start
            if not line.strip():
                continue
            # Stop skipping after first real content
            skip_metadata = False

        cleaned_lines.append(line)

    lines = cleaned_lines
    structure = {
        'title': '',
        'sections': [],
        'tables': []
    }

    current_section = None
    in_code_block = False
    code_lines = []
    current_list = []
    list_depth = 0
    current_text = []
    in_table = False
    table_rows = []

    def save_current_list():
        """Helper to save accumulated list items."""
        nonlocal current_list
        if current_list and current_section:
            current_section.setdefault('lists', []).append(current_list)
            current_list = []

    def save_current_section():
        """Helper to save current section."""
        nonlocal current_text
        if current_section:
            current_section['text'] = '\n'.join(current_text).strip()
            save_current_list()
            structure['sections'].append(current_section)
            current_text = []

    for line in lines:
        # Code block detection
        if line.strip().startswith('```'):
            if in_code_block:
                # End code block
                if current_section:
                    current_section.setdefault('code_blocks', []).append('\n'.join(code_lines))
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
                save_current_list()  # Save any pending list
            continue

        if in_code_block:
            code_lines.append(line)
            continue

        # Table detection (basic markdown tables)
        if re.match(r'^\s*\|.*\|\s*$', line):
            if not in_table:
                in_table = True
                save_current_list()
            # Parse table row
            cells = [cell.strip() for cell in line.strip('|').split('|')]
            # Skip separator rows (like |---|---|)
            if not all(re.match(r'^:?-+:?$', cell) for cell in cells):
                table_rows.append(cells)
            continue
        elif in_table:
            # End of table
            if current_section and table_rows:
                current_section.setdefault('tables', []).append(table_rows)
            table_rows = []
            in_table = False

        # Heading detection
        if match := re.match(r'^(#{1,6})\s+(.+)$', line):
            save_current_section()

            level = len(match.group(1))
            heading = match.group(2).strip()

            # Remove markdown links from heading
            heading = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', heading)

            if level == 1 and not structure['title']:
                structure['title'] = heading
            else:
                current_section = {
                    'heading': heading,
                    'level': level,
                    'text': '',
                    'code_blocks': [],
                    'lists': [],
                    'tables': [],
                    'links': []
                }
            continue

        # Nested list detection (up to 3 levels)
        if match := re.match(r'^([\s]*)[-*+]\s+(.+)$', line):
            indent = len(match.group(1))
            item_text = match.group(2).strip()

            # Extract links from list items
            if current_section:
                links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', item_text)
                for link_text, link_url in links:
                    current_section['links'].append({'text': link_text, 'url': link_url})

            # Determine nesting level (0, 2, 4 spaces = levels 0, 1, 2)
            depth = min(indent // 2, 2)

            # Create nested structure if needed
            if depth > list_depth:
                # Starting nested list
                if current_list:
                    nested_item = {'text': current_list[-1], 'children': [item_text]}
                    current_list[-1] = nested_item
                else:
                    current_list.append(item_text)
            elif depth < list_depth:
                # Ending nested list
                current_list.append(item_text)
            else:
                current_list.append(item_text)

            list_depth = depth
            continue

        # Numbered list (with nesting support)
        if match := re.match(r'^([\s]*)\d+\.\s+(.+)$', line):
            indent = len(match.group(1))
            item_text = match.group(2).strip()

            # Extract links
            if current_section:
                links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', item_text)
                for link_text, link_url in links:
                    current_section['links'].append({'text': link_text, 'url': link_url})

            current_list.append(item_text)
            continue

        # Regular text
        if line.strip():
            # Extract links from regular text
            if current_section:
                links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', line)
                for link_text, link_url in links:
                    current_section['links'].append({'text': link_text, 'url': link_url})

            current_text.append(line.strip())
        elif current_list:
            save_current_list()
            list_depth = 0

    # Save final section
    save_current_section()

    # Handle edge case: if no sections but have title, create one section
    if not structure['sections'] and structure['title']:
        structure['sections'].append({
            'heading': 'Overview',
            'level': 2,
            'text': 'Content from ' + structure['title'],
            'code_blocks': [],
            'lists': [],
            'tables': [],
            'links': []
        })

    return structure


def clean_markdown_formatting(text: str) -> str:
    """Remove markdown formatting from text.

    Args:
        text: Text with markdown formatting

    Returns:
        Plain text without markdown
    """
    # Remove bold
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
    # Remove italic
    text = re.sub(r'\*([^*]+)\*', r'\1', text)
    # Remove code
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Remove links
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    return text.strip()


def is_metadata_line(text: str) -> bool:
    """Check if a line is metadata that should be filtered.

    Args:
        text: Text line to check

    Returns:
        True if line is metadata
    """
    text = text.strip()
    # Check for Generated: lines
    if re.match(r'^\*?Generated:.*\*?$', text, re.IGNORECASE):
        return True
    # Check for horizontal rules
    if re.match(r'^[-*_]{3,}$', text):
        return True
    return False


__all__ = [
    'parse_markdown_structure',
    'clean_markdown_formatting',
    'is_metadata_line'
]
