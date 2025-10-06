"""
Document Input Adapter
======================
Parse markdown documents, READMEs, and text files into video sets.

Supports:
- Local markdown/text files
- GitHub URLs (converts to raw URLs)
- Intelligent section detection
- Command/code extraction
- List detection
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from .base import BaseInputAdapter, VideoSet, VideoConfig

logger = logging.getLogger(__name__)

# Try to import requests for URL fetching
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class DocumentAdapter(BaseInputAdapter):
    """Adapter for parsing markdown/text documents"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.max_scenes = kwargs.get('max_scenes', 6)
        self.target_duration = kwargs.get('target_duration', 60)

    def parse(self, source: str, **options) -> VideoSet:
        """
        Parse document into VideoSet.

        Args:
            source: File path or URL to document
            **options: Parsing options (max_scenes, target_duration, etc.)

        Returns:
            VideoSet with parsed content
        """
        # Read document content
        content = self._read_document(source)

        # Parse markdown structure
        structure = self._parse_markdown(content)

        # Extract video metadata
        set_id = options.get('set_id') or self._generate_set_id(source, structure)
        set_name = options.get('set_name') or structure.get('title', 'Document Video')

        # Convert structure to scenes
        scenes = self._structure_to_scenes(structure)

        # Create video config
        video = VideoConfig(
            video_id=f"{set_id}_main",
            title=structure.get('title', 'Documentation'),
            description=f"Video generated from {source}",
            scenes=scenes
        )

        # Create and return video set
        return self.create_video_set(
            set_id=set_id,
            set_name=set_name,
            videos=[video],
            description=options.get('description', f'Videos from {source}'),
            defaults={
                'accent_color': options.get('accent_color', 'blue'),
                'voice': options.get('voice', 'male'),
                'target_duration': self.target_duration,
                'min_scene_duration': 3.0,
                'max_scene_duration': 15.0
            }
        )

    def _read_document(self, source: str) -> str:
        """Read document from file or URL"""
        if source.startswith('http://') or source.startswith('https://'):
            if not HAS_REQUESTS:
                raise ImportError("requests library required for URL fetching. Install: pip install requests")

            # Convert GitHub URLs to raw URLs
            url = self._convert_github_url(source)

            logger.info(f"Fetching from URL: {url}")
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                return response.text
            except requests.Timeout:
                raise ValueError(f"Request timed out after 30 seconds: {url}")
            except requests.RequestException as e:
                raise ValueError(f"Failed to fetch URL: {url}. Error: {e}")
        else:
            logger.info(f"Reading file: {source}")
            with open(source, 'r', encoding='utf-8') as f:
                return f.read()

    def _convert_github_url(self, url: str) -> str:
        """Convert GitHub blob URLs to raw URLs"""
        if 'github.com' in url and '/blob/' in url:
            url = url.replace('github.com', 'raw.githubusercontent.com')
            url = url.replace('/blob/', '/')
        return url

    def _generate_set_id(self, source: str, structure: Dict) -> str:
        """Generate set ID from source or title"""
        if source.startswith('http'):
            # Extract from URL
            parts = source.rstrip('/').split('/')
            set_id = parts[-1].replace('.md', '').replace('.txt', '')
        else:
            # Extract from filename
            set_id = Path(source).stem

        # Clean up
        set_id = re.sub(r'[^a-z0-9_-]', '_', set_id.lower())
        return set_id

    def _parse_markdown(self, content: str) -> Dict:
        """Parse markdown into structured format"""
        lines = content.split('\n')

        structure = {
            'title': '',
            'sections': []
        }

        current_section = None
        in_code_block = False
        code_block_lines = []
        current_list = []
        current_paragraph = []

        for line in lines:
            # Code block detection
            if line.strip().startswith('```'):
                if in_code_block:
                    # End of code block
                    if current_section:
                        if 'code_blocks' not in current_section:
                            current_section['code_blocks'] = []
                        current_section['code_blocks'].append('\n'.join(code_block_lines))
                    code_block_lines = []
                    in_code_block = False
                else:
                    # Start of code block
                    in_code_block = True
                continue

            if in_code_block:
                code_block_lines.append(line)
                continue

            # Heading detection
            heading_match = re.match(r'^(#{1,6})\s+(.+)$', line)
            if heading_match:
                # Save previous section
                if current_section:
                    current_section['text'] = '\n'.join(current_paragraph).strip()
                    if current_list:
                        current_section['lists'] = current_section.get('lists', [])
                        current_section['lists'].append(current_list)
                        current_list = []
                    structure['sections'].append(current_section)
                    current_paragraph = []

                level = len(heading_match.group(1))
                heading_text = heading_match.group(2).strip()

                if level == 1 and not structure['title']:
                    structure['title'] = heading_text
                else:
                    current_section = {
                        'heading': heading_text,
                        'level': level,
                        'text': '',
                        'code_blocks': [],
                        'lists': []
                    }
                continue

            # List detection
            list_match = re.match(r'^[\s]*[-*+]\s+(.+)$', line)
            if list_match:
                current_list.append(list_match.group(1).strip())
                continue

            # Numbered list
            num_list_match = re.match(r'^[\s]*\d+\.\s+(.+)$', line)
            if num_list_match:
                current_list.append(num_list_match.group(1).strip())
                continue

            # Regular paragraph
            if line.strip():
                current_paragraph.append(line.strip())
            elif current_list:
                # Empty line ends list
                if current_section:
                    current_section['lists'] = current_section.get('lists', [])
                    current_section['lists'].append(current_list)
                current_list = []

        # Save final section
        if current_section:
            current_section['text'] = '\n'.join(current_paragraph).strip()
            if current_list:
                current_section['lists'] = current_section.get('lists', [])
                current_section['lists'].append(current_list)
            structure['sections'].append(current_section)

        return structure

    def _structure_to_scenes(self, structure: Dict) -> List[Dict[str, Any]]:
        """Convert document structure to video scenes"""
        scenes = []

        # Scene 1: Title
        if structure['title']:
            title_scene = self.create_scene(
                scene_type='title',
                visual_content={
                    'title': structure['title'],
                    'subtitle': self._generate_subtitle(structure)
                }
            )
            scenes.append(title_scene)

        # Convert sections to scenes (limit to max_scenes - 2 for title + outro)
        sections_to_use = structure['sections'][:self.max_scenes - 2]

        for section in sections_to_use:
            scene = self._section_to_scene(section)
            if scene:
                scenes.append(scene)

        # Final scene: Outro
        outro_scene = self.create_scene(
            scene_type='outro',
            visual_content={
                'main_text': 'Learn More',
                'sub_text': 'See Documentation'
            }
        )
        scenes.append(outro_scene)

        return scenes

    def _generate_subtitle(self, structure: Dict) -> str:
        """Generate subtitle from first section"""
        if structure['sections']:
            first_text = structure['sections'][0].get('text', '')
            sentences = re.split(r'[.!?]', first_text)
            if sentences and sentences[0]:
                return sentences[0].strip()[:50]
        return "Complete Guide"

    def _section_to_scene(self, section: Dict) -> Optional[Dict[str, Any]]:
        """Convert section to appropriate scene type"""
        heading = section['heading']
        has_code = len(section.get('code_blocks', [])) > 0
        has_lists = len(section.get('lists', [])) > 0

        if has_code:
            # Command scene
            commands = self._extract_commands(section['code_blocks'])

            return self.create_scene(
                scene_type='command',
                visual_content={
                    'header': heading,
                    'description': self._summarize_text(section['text'], max_words=8),
                    'commands': commands
                }
            )

        elif has_lists:
            # List scene
            items = []
            for lst in section['lists']:
                for item in lst[:5]:  # Max 5 items
                    items.append(item)

            return self.create_scene(
                scene_type='list',
                visual_content={
                    'header': heading,
                    'description': self._summarize_text(section['text'], max_words=6),
                    'items': items
                }
            )

        elif section.get('text'):
            # Text-only section - extract key points
            key_points = self._extract_key_points(section['text'])

            if key_points:
                return self.create_scene(
                    scene_type='list',
                    visual_content={
                        'header': heading,
                        'description': self._summarize_text(section['text'], max_words=8),
                        'items': key_points[:5]
                    }
                )

        return None

    def _extract_commands(self, code_blocks: List[str]) -> List[str]:
        """Extract commands from code blocks"""
        commands = []

        for block in code_blocks:
            lines = block.split('\n')
            for line in lines[:10]:  # Max 10 lines
                line = line.strip()
                if line and not line.startswith('#'):
                    # Format as command
                    if not line.startswith('$'):
                        line = '$ ' + line
                    commands.append(line)

        return commands[:6]  # Max 6 commands per scene

    def _extract_key_points(self, text: str) -> List[str]:
        """Extract key points from text"""
        if not text:
            return []

        # Split into sentences
        sentences = re.split(r'[.!?]+', text)

        key_points = []
        for sentence in sentences[:5]:
            sentence = sentence.strip()
            if sentence and len(sentence.split()) < 15:  # Short sentences = key points
                # Clean up
                sentence = sentence.replace('\n', ' ')
                sentence = re.sub(r'\s+', ' ', sentence)
                key_points.append(sentence)

        return key_points

    def _summarize_text(self, text: str, max_words: int = 8) -> str:
        """Summarize text to max_words"""
        if not text:
            return ""

        words = text.split()[:max_words]
        return ' '.join(words)
