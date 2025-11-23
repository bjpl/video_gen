"""Document input adapter for PDF, DOCX, and text files.

This adapter processes document files and extracts structured content for
video generation with AI-enhanced slide content.
"""

from pathlib import Path
from typing import Any, List, Optional
import re  # For markdown cleaning
import asyncio
import logging

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, SceneConfig
from ..script_generator.ai_enhancer import AIScriptEnhancer


class DocumentAdapter(InputAdapter):
    """Adapter for document files (PDF, DOCX, TXT, Markdown).

    This adapter reads document files, extracts text and structure, and
    converts them into VideoSet objects for video generation with AI-enhanced
    slide content and narration.
    """

    def __init__(self, test_mode: bool = False, use_ai: bool = True, ai_api_key: Optional[str] = None):
        """Initialize the document adapter.

        Args:
            test_mode: If True, bypass security checks for testing purposes.
                      This allows reading files outside the project directory.
            use_ai: If True, use AI enhancement for slide content and narration.
            ai_api_key: Optional Anthropic API key for AI enhancement.
        """
        super().__init__(
            name="document",
            description="Processes PDF, DOCX, TXT, and Markdown files with AI enhancement"
        )

        # Set up logger
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.supported_formats = {".pdf", ".docx", ".txt", ".md"}
        self.test_mode = test_mode
        self.use_ai = use_ai

        # Initialize AI enhancer if requested
        self.ai_enhancer: Optional[AIScriptEnhancer] = None
        if use_ai:
            try:
                self.ai_enhancer = AIScriptEnhancer(api_key=ai_api_key)
                self.logger.info("AI enhancement enabled for slide content")
            except Exception as e:
                self.logger.warning(f"AI enhancement initialization failed: {e}")
                self.use_ai = False

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt a document file to VideoSet structure.

        Args:
            source: Path to document file or URL
            **kwargs: Additional parameters (accent_color, voice, etc.)

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Read document content (file or URL)
            content = await self._read_document_content(source)

            if not content:
                return InputAdapterResult(
                    success=False,
                    error=f"Failed to read document: {source}"
                )

            # Parse markdown structure
            structure = self._parse_markdown_structure(content)

            # Generate video set from structure (with AI enhancement)
            video_set = await self._create_video_set_from_structure(
                structure,
                source,
                **kwargs
            )

            return InputAdapterResult(
                success=True,
                video_set=video_set,
                metadata={
                    "source": str(source),
                    "sections_found": len(structure.get('sections', [])),
                    "videos_generated": len(video_set.videos)
                }
            )

        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"Document adaptation failed: {str(e)}"
            )

    async def _read_document_content(self, source: Any) -> str:
        """Read document from file or URL with security validation."""
        # Clean the source path - strip quotes and whitespace
        source_str = str(source).strip().strip('"').strip("'")

        # Check if URL
        if source_str.startswith('http://') or source_str.startswith('https://'):
            # Try to import requests
            try:
                import requests
                from urllib.parse import urlparse
                import socket

                # URL validation - only http/https allowed
                parsed = urlparse(source_str)
                if parsed.scheme not in ['http', 'https']:
                    raise ValueError(f"Invalid URL scheme: {parsed.scheme} (only http/https allowed)")

                # SSRF Protection: Block internal/private IP addresses
                try:
                    ip = socket.gethostbyname(parsed.hostname)
                    # Block private IP ranges
                    if (ip.startswith('127.') or ip.startswith('192.168.') or
                        ip.startswith('10.') or ip.startswith('172.16.') or
                        ip.startswith('169.254.') or ip == 'localhost'):
                        raise ValueError(f"Internal/private URLs not allowed for security: {ip}")
                except socket.gaierror:
                    pass  # DNS lookup failed, let requests handle it

                # Convert GitHub URLs to raw
                url = source_str
                if 'github.com' in url and '/blob/' in url:
                    url = url.replace('github.com', 'raw.githubusercontent.com')
                    url = url.replace('/blob/', '/')

                # Fetch with size limit check
                response = requests.get(url, timeout=10, stream=True)
                response.raise_for_status()

                # Check content length before reading
                content_length = int(response.headers.get('content-length', 0))
                MAX_FILE_SIZE = 10_000_000  # 10MB limit
                if content_length > MAX_FILE_SIZE:
                    raise ValueError(f"Document too large: {content_length} bytes (max {MAX_FILE_SIZE})")

                # Read content with size limit
                content = response.text
                if len(content) > MAX_FILE_SIZE:
                    raise ValueError(f"Document too large: {len(content)} bytes (max {MAX_FILE_SIZE})")

                return content

            except ImportError:
                raise Exception("requests library required for URL fetching. Install: pip install requests")
            except Exception as e:
                raise Exception(f"Failed to fetch URL: {e}")
        else:
            # Read from file with path traversal protection
            file_path = Path(source_str)

            # Security: Resolve to absolute path to detect traversal attempts
            try:
                file_path = file_path.resolve()
            except (OSError, RuntimeError) as e:
                raise ValueError(f"Invalid file path: {e}")

            # Get workspace root (allow access to sibling projects)
            # This file is in: video_gen/video_gen/input_adapters/document.py
            # Project root: video_gen/
            # Workspace root: active-development/ (4 levels up)
            project_root = Path(__file__).parent.parent.parent.resolve()  # video_gen/
            workspace_root = project_root.parent.resolve()  # active-development/

            # CRITICAL SECURITY: Block absolute paths to system directories
            # This prevents access to sensitive files like /etc/passwd, /root/.ssh/id_rsa, etc.
            system_dirs = ['/etc', '/sys', '/proc', '/root', '/boot', '/var', '/usr', '/bin', '/sbin']
            file_path_str = str(file_path)
            if any(file_path_str.startswith(d) for d in system_dirs):
                raise ValueError(f"Access to system directories denied: {file_path}")

            # Path traversal protection: Ensure file is under workspace root
            # This allows access to sibling projects (e.g., corporate_intel, language-learning)
            # Skip this check in test mode to allow temporary test files
            if not self.test_mode:
                try:
                    file_path.relative_to(workspace_root)
                except ValueError:
                    raise ValueError(f"Path traversal detected: {file_path} is outside workspace directory ({workspace_root})")

            # Validate file exists and is actually a file
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            if not file_path.is_file():
                raise ValueError(f"Not a file: {file_path}")

            # File size limit (10MB)
            MAX_FILE_SIZE = 10_000_000
            file_size = file_path.stat().st_size
            if file_size > MAX_FILE_SIZE:
                raise ValueError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

            # Detect binary files by checking for common binary signatures
            with open(file_path, 'rb') as f:
                header = f.read(16)
                # Check for common binary file signatures
                binary_signatures = [
                    (b'\xff\xd8\xff', 'JPEG image'),
                    (b'\x89PNG', 'PNG image'),
                    (b'GIF8', 'GIF image'),
                    (b'%PDF', 'PDF document'),
                    (b'PK\x03\x04', 'ZIP archive (DOCX/XLSX)'),
                    (b'\x00\x00\x00', 'MP4/MP3/other binary'),
                ]

                for sig, file_type in binary_signatures:
                    if header.startswith(sig):
                        raise ValueError(
                            f"Binary file detected: {file_type}. "
                            f"Please upload a text file (.md, .txt) instead of '{file_path.name}'"
                        )

            # Try to read as UTF-8 with better error handling
            try:
                return file_path.read_text(encoding='utf-8')
            except UnicodeDecodeError as e:
                # Try other common encodings
                for encoding in ['utf-16', 'latin-1', 'cp1252']:
                    try:
                        content = file_path.read_text(encoding=encoding)
                        self.logger.warning(f"File decoded using {encoding} instead of UTF-8")
                        return content
                    except:
                        continue

                # If all encodings fail, provide helpful error
                raise ValueError(
                    f"Unable to read file '{file_path.name}'. "
                    f"The file appears to be binary or uses an unsupported text encoding. "
                    f"Please ensure you're uploading a plain text or markdown file."
                )

    def _parse_markdown_structure(self, content: str) -> dict:
        """Parse markdown content into structured format.

        Enhanced with support for:
        - Nested lists (up to 3 levels)
        - Tables (basic markdown tables)
        - Better handling of malformed markdown
        - Link extraction
        - Metadata stripping (Generated:, dates, etc.)
        """
        import re

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
            nonlocal current_list, current_section
            if current_list and current_section:
                current_section.setdefault('lists', []).append(current_list)
                current_list = []

        def save_current_section():
            """Helper to save current section."""
            nonlocal current_section, current_text, current_list
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

    async def _create_video_set_from_structure(self, structure: dict, source: Any, **kwargs) -> VideoSet:
        """Create VideoSet from parsed structure with AI enhancement.

        Enhanced to support:
        - Multiple videos split by ## headings (level 2)
        - Tables rendered as comparison scenes
        - Better scene distribution
        - Max scenes per video configuration
        - AI-enhanced slide content and narration
        """
        import re
        from ..shared.models import VideoSet, VideoConfig

        # Generate set ID
        if isinstance(source, str) and source.startswith('http'):
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())
        else:
            set_id = re.sub(r'[^a-z0-9_-]', '_', Path(source).stem.lower())

        set_name = structure.get('title', 'Document Video')
        accent_color = kwargs.get('accent_color', 'blue')
        voice = kwargs.get('voice', 'male')
        max_scenes_per_video = kwargs.get('max_scenes_per_video', 50)  # Increased to 50 for comprehensive single videos
        split_by_h2 = kwargs.get('split_by_h2', False)  # Default: create ONE comprehensive video with all sections
        video_count = kwargs.get('video_count', None)  # User-specified number of videos (optional)

        # Group sections by level 2 headings if split_by_h2 is enabled OR if video_count > 1
        video_groups = []
        should_split = (split_by_h2 or (video_count and video_count > 1)) and any(s.get('level') == 2 for s in structure['sections'])

        if should_split:
            current_group = []
            current_h2 = None

            for section in structure['sections']:
                if section.get('level') == 2:
                    if current_group:
                        video_groups.append({
                            'title': current_h2,
                            'sections': current_group
                        })
                    current_h2 = section['heading']
                    current_group = [section]
                else:
                    if current_group or current_h2:
                        current_group.append(section)

            if current_group:
                video_groups.append({
                    'title': current_h2,
                    'sections': current_group
                })

            # If user specified exact video count AND split_by_h2 is False, merge groups to match
            # When split_by_h2=True, always create one video per H2 section (ignore video_count)
            if not split_by_h2 and video_count and len(video_groups) > video_count:
                # Merge excess groups into video_count groups
                groups_per_video = len(video_groups) // video_count
                merged_groups = []
                for i in range(0, len(video_groups), groups_per_video):
                    chunk = video_groups[i:i + groups_per_video]
                    merged_sections = []
                    titles = []
                    for grp in chunk:
                        merged_sections.extend(grp['sections'])
                        titles.append(grp['title'])
                    merged_groups.append({
                        'title': ' + '.join(titles[:2]) if len(titles) > 1 else titles[0],
                        'sections': merged_sections
                    })
                video_groups = merged_groups[:video_count]
        else:
            # Single video with all sections
            video_groups = [{
                'title': set_name,
                'sections': structure['sections']
            }]

        # Create videos from groups
        videos = []
        for group_idx, group in enumerate(video_groups):
            video_id = f"{set_id}_video_{group_idx}" if len(video_groups) > 1 else f"{set_id}_main"
            video_title = group['title'] if len(video_groups) > 1 else set_name

            scenes = await self._create_scenes_from_sections(
                sections=group['sections'],
                video_id=video_id,
                title=structure['title'],
                subtitle=group['title'],
                voice=voice,
                max_scenes=max_scenes_per_video
            )

            if scenes:  # Only add video if it has scenes
                video = VideoConfig(
                    video_id=video_id,
                    title=video_title,
                    description=f"Generated from {source}",
                    scenes=scenes,
                    accent_color=accent_color
                )
                videos.append(video)

        # Return video set
        # Store custom options in metadata for backward compatibility with config.defaults
        return VideoSet(
            set_id=set_id,
            name=set_name,
            description=f"Videos generated from document: {source}",
            videos=videos,
            metadata={
                "source": str(source),
                "video_count": len(videos),
                "total_sections": len(structure['sections']),
                # Store custom options for config.defaults backward compat
                "accent_color": accent_color,
                "voice": voice
            }
        )

    async def _create_scenes_from_sections(
        self,
        sections: List[dict],
        video_id: str,
        title: str,
        subtitle: str,
        voice: str,
        max_scenes: int = 8
    ) -> List['SceneConfig']:
        """Create scenes from a list of sections with AI-enhanced content."""
        from ..shared.models import SceneConfig

        scenes = []
        total_scenes = min(len(sections) + 2, max_scenes)  # +2 for title and outro

        # Title scene with AI enhancement
        title_text = await self._enhance_slide_content(
            title,
            context_type="title",
            scene_position=0,
            total_scenes=total_scenes
        )
        subtitle_text = await self._enhance_slide_content(
            subtitle or 'Complete Guide',
            context_type="subtitle",
            scene_position=0,
            total_scenes=total_scenes
        )
        title_narration = await self._enhance_narration(
            f"Welcome to {subtitle or title}",
            scene_type="title",
            scene_data={'title': title_text, 'subtitle': subtitle_text},
            scene_position=0,
            total_scenes=total_scenes
        )

        scenes.append(SceneConfig(
            scene_id=f"{video_id}_title",
            scene_type="title",
            narration=title_narration,
            visual_content={
                'title': title_text,
                'subtitle': subtitle_text
            },
            voice=voice
        ))

        # Convert sections to scenes (limit by max_scenes - 2 for title and outro)
        content_scenes = max_scenes - 2
        for i, section in enumerate(sections[:content_scenes]):
            scene_position = i + 1  # +1 because title is scene 0
            heading = section['heading']
            has_code = len(section.get('code_blocks', [])) > 0
            has_lists = len(section.get('lists', [])) > 0
            has_tables = len(section.get('tables', [])) > 0

            if has_tables:
                # Convert table to list scene with AI enhancement
                table = section['tables'][0]  # Use first table
                if len(table) >= 2:  # Need at least header and one row
                    # Format table rows as "label: value" items
                    items = []
                    for row in table[1:5]:  # Skip header, take up to 4 rows
                        if row:
                            if len(row) > 1:
                                item = f"{row[0]}: {' | '.join(row[1:])}"
                            else:
                                item = row[0]
                            # Clean markdown formatting
                            item = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', item)  # [text](url) → text
                            item = re.sub(r'\*\*([^*]+)\*\*', r'\1', item)  # **bold** → text
                            item = re.sub(r'\*([^*]+)\*', r'\1', item)  # *italic* → text
                            item = re.sub(r'`([^`]+)`', r'\1', item)  # `code` → code
                            items.append(item)

                    # AI enhance visual content
                    enhanced_header = await self._enhance_slide_content(
                        heading, "header", scene_position, total_scenes
                    )
                    enhanced_desc = await self._enhance_slide_content(
                        section['text'][:100] if section['text'] else 'Key comparisons',
                        "description", scene_position, total_scenes
                    )
                    enhanced_narration = await self._enhance_narration(
                        f"Here's a comparison of {heading.lower()}",
                        "list",
                        {'header': enhanced_header, 'items': items},
                        scene_position,
                        total_scenes
                    )

                    scenes.append(SceneConfig(
                        scene_id=f"{video_id}_list_{i}",
                        scene_type="list",
                        narration=enhanced_narration,
                        visual_content={
                            'header': enhanced_header,
                            'description': enhanced_desc,
                            'items': items
                        },
                        voice=voice
                    ))

            elif has_code:
                # Command scene with AI enhancement
                commands = []
                for block in section['code_blocks']:
                    for line in block.split('\n')[:6]:
                        if line.strip() and not line.strip().startswith('#'):
                            commands.append(line.strip())

                # AI enhance visual content (clean metadata first)
                section_text = section['text'] if section['text'] else ''
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                enhanced_header = await self._enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self._enhance_slide_content(
                    section_text[:100],
                    "description", scene_position, total_scenes
                )
                enhanced_narration = await self._enhance_narration(
                    f"Here's how to {heading.lower()}",
                    "command",
                    {'header': enhanced_header, 'commands': commands},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_command_{i}",
                    scene_type="command",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'commands': commands[:6]
                    },
                    voice=voice
                ))

            elif has_lists:
                # List scene with AI enhancement
                items = []
                for lst in section['lists']:
                    # Flatten nested lists
                    for item in lst:
                        if isinstance(item, dict) and 'text' in item:
                            clean_item = item['text']
                        else:
                            clean_item = str(item)

                        # Clean markdown formatting
                        clean_item = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', clean_item)  # [text](url) → text
                        clean_item = re.sub(r'\*\*([^*]+)\*\*', r'\1', clean_item)  # **bold** → text
                        clean_item = re.sub(r'\*([^*]+)\*', r'\1', clean_item)  # *italic* → text
                        clean_item = re.sub(r'`([^`]+)`', r'\1', clean_item)  # `code` → code

                        # CRITICAL: Remove metadata patterns from items
                        # Skip items that are just metadata
                        if re.match(r'^\*?Generated:.*\*?$', clean_item.strip(), re.IGNORECASE):
                            continue  # Skip this item entirely
                        if re.match(r'^[-*_]{3,}$', clean_item.strip()):
                            continue  # Skip horizontal rules

                        # Only add non-empty, non-metadata items
                        if clean_item.strip():
                            items.append(clean_item)

                # Create narration that describes the list content
                items_preview = items[:3] if len(items) > 3 else items
                narration = f"This section covers {heading.lower()}: {', '.join(items_preview)}"
                if len(items) > 3:
                    narration += f", and {len(items) - 3} more topics"

                # AI enhance visual content (clean metadata first)
                section_text = section['text'] if section['text'] else ''
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                enhanced_header = await self._enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self._enhance_slide_content(
                    section_text[:100],
                    "description", scene_position, total_scenes
                )
                enhanced_narration = await self._enhance_narration(
                    narration,
                    "list",
                    {'header': enhanced_header, 'items': items[:5]},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'items': items[:5]  # Limit to 5 items
                    },
                    voice=voice
                ))

            elif section['text']:
                # Text to list scene with AI enhancement
                # First, remove metadata from section text
                section_text = section['text']
                section_text = re.sub(r'\*?Generated:.*\*?', '', section_text, flags=re.IGNORECASE)
                section_text = re.sub(r'^[-*_]{3,}$', '', section_text, flags=re.MULTILINE)
                section_text = section_text.strip()

                sentences = [s.strip() for s in section_text.split('.') if s.strip()]
                # Clean markdown from sentences
                clean_sentences = []
                for sent in sentences:
                    # Skip metadata sentences
                    if re.match(r'^\*?Generated:.*\*?$', sent.strip(), re.IGNORECASE):
                        continue
                    if re.match(r'^[-*_]{3,}$', sent.strip()):
                        continue

                    clean = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', sent)
                    clean = re.sub(r'\*\*([^*]+)\*\*', r'\1', clean)
                    clean = re.sub(r'\*([^*]+)\*', r'\1', clean)
                    clean = re.sub(r'`([^`]+)`', r'\1', clean)

                    if clean.strip():  # Only add non-empty sentences
                        clean_sentences.append(clean)

                # AI enhance visual content
                enhanced_header = await self._enhance_slide_content(
                    heading, "header", scene_position, total_scenes
                )
                enhanced_desc = await self._enhance_slide_content(
                    clean_sentences[0] if clean_sentences else '',
                    "description", scene_position, total_scenes
                )
                text_items = clean_sentences[1:4] if len(clean_sentences) > 1 else [section['text'][:100]]
                enhanced_narration = await self._enhance_narration(
                    f"About {heading.lower()}",
                    "list",
                    {'header': enhanced_header, 'items': text_items},
                    scene_position,
                    total_scenes
                )

                scenes.append(SceneConfig(
                    scene_id=f"{video_id}_list_{i}",
                    scene_type="list",
                    narration=enhanced_narration,
                    visual_content={
                        'header': enhanced_header,
                        'description': enhanced_desc,
                        'items': text_items
                    },
                    voice=voice
                ))

        # Outro scene with AI enhancement
        outro_main = await self._enhance_slide_content(
            'Learn More',
            context_type="outro_main",
            scene_position=len(scenes),
            total_scenes=total_scenes
        )
        outro_sub = await self._enhance_slide_content(
            'See Full Documentation',
            context_type="outro_sub",
            scene_position=len(scenes),
            total_scenes=total_scenes
        )
        outro_narration = await self._enhance_narration(
            "Thanks for watching! Check out the documentation for more details.",
            scene_type="outro",
            scene_data={'main_text': outro_main, 'sub_text': outro_sub},
            scene_position=len(scenes),
            total_scenes=total_scenes
        )

        scenes.append(SceneConfig(
            scene_id=f"{video_id}_outro",
            scene_type="outro",
            narration=outro_narration,
            visual_content={
                'main_text': outro_main,
                'sub_text': outro_sub
            },
            voice=voice
        ))

        return scenes

    async def _enhance_slide_content(
        self,
        content: str,
        context_type: str,
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Enhance slide content (titles, headers, descriptions) using AI.

        Args:
            content: Original content text
            context_type: Type of content (title, subtitle, header, description, etc.)
            scene_position: Position of scene in video (0-indexed)
            total_scenes: Total number of scenes

        Returns:
            Enhanced content text - KEPT SHORT for on-screen display
        """
        # Clean markdown artifacts from content FIRST
        import re
        content = re.sub(r'\*\*([^*]+)\*\*', r'\1', content)  # **bold**
        content = re.sub(r'\*([^*]+)\*', r'\1', content)  # *italic*
        content = re.sub(r'`([^`]+)`', r'\1', content)  # `code`
        content = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', content)  # [text](url)
        content = content.strip()

        # For slide display text, DON'T use AI enhancement - keep it short and clean
        # AI enhancement is designed for narration (long paragraphs), not slide titles
        # This prevents titles like "How the Internet Works" from becoming long paragraphs
        if context_type in ("title", "subtitle", "header", "outro_main", "outro_sub"):
            # Just clean and limit length
            max_lengths = {
                "title": 60,
                "subtitle": 80,
                "header": 70,
                "outro_main": 50,
                "outro_sub": 60
            }
            max_len = max_lengths.get(context_type, 100)
            if len(content) > max_len:
                content = content[:max_len].rsplit(' ', 1)[0] + '...'
            return content

        # For descriptions, allow AI but with strict length control
        if not self.use_ai or not self.ai_enhancer:
            return content[:150]  # Limit to 150 chars

        try:
            # Create context for AI enhancement
            context = {
                'scene_position': scene_position,
                'total_scenes': total_scenes,
                'content_type': context_type,
                'max_length': 150  # Force AI to keep descriptions short
            }

            # Use AI to enhance the description only (not titles/headers)
            enhanced = await self.ai_enhancer.enhance_script(
                script=content,
                scene_type=context_type,
                context=context
            )

            # Enforce length limit even if AI ignores it
            if len(enhanced) > 150:
                enhanced = enhanced[:150].rsplit(' ', 1)[0] + '...'

            return enhanced

        except Exception as e:
            self.logger.warning(f"Slide content AI enhancement failed: {e}, using original")
            return content[:150]

    async def _enhance_narration(
        self,
        narration: str,
        scene_type: str,
        scene_data: dict,
        scene_position: int = 0,
        total_scenes: int = 1
    ) -> str:
        """Enhance narration using AI.

        Args:
            narration: Original narration text
            scene_type: Type of scene
            scene_data: Scene visual content data
            scene_position: Position of scene in video (0-indexed)
            total_scenes: Total number of scenes

        Returns:
            Enhanced narration text
        """
        if not self.use_ai or not self.ai_enhancer:
            return narration

        try:
            # Create context for AI enhancement
            context = {
                'scene_position': scene_position,
                'total_scenes': total_scenes,
                **scene_data
            }

            # Use AI to enhance the narration
            enhanced = await self.ai_enhancer.enhance_script(
                script=narration,
                scene_type=scene_type,
                context=context
            )

            return enhanced

        except Exception as e:
            self.logger.warning(f"Narration AI enhancement failed: {e}, using original")
            return narration

    async def validate_source(self, source: Any) -> bool:
        """Validate document file.

        Args:
            source: Path to document file

        Returns:
            True if valid, False otherwise
        """
        if not isinstance(source, (str, Path)):
            return False

        file_path = Path(source)
        return (
            file_path.exists()
            and file_path.is_file()
            and file_path.suffix.lower() in self.supported_formats
        )

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: File extension (e.g., ".pdf")

        Returns:
            True if supported
        """
        return format_type.lower() in self.supported_formats
