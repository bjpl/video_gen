"""
Document to Video Script Generator
===================================
Converts existing documentation (README, guides, markdown) into video scripts.

Supports:
- Local markdown files
- Plain text files
- GitHub URLs (raw.githubusercontent.com)
- Intelligent scene structuring
- Auto-generated narration

Usage:
    python generate_script_from_document.py README.md
    python generate_script_from_document.py https://github.com/user/repo/blob/main/README.md
"""

import re
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
import logging

# Setup logging
logger = logging.getLogger(__name__)


# Try to import requests for URL fetching
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    logger.warning("⚠️  Install 'requests' for URL support: pip install requests")

def read_document(source):
    """Read document from file or URL"""
    if source.startswith('http://') or source.startswith('https://'):
        if not HAS_REQUESTS:
            raise ImportError("requests library required for URL fetching")

        # Convert GitHub URLs to raw URLs
        if 'github.com' in source and '/blob/' in source:
            source = source.replace('github.com', 'raw.githubusercontent.com')
            source = source.replace('/blob/', '/')

        logger.info(f"Fetching from URL: {source}")
        response = requests.get(source)
        response.raise_for_status()
        return response.text
    else:
        logger.info(f"Reading file: {source}")
        with open(source, 'r', encoding='utf-8') as f:
            return f.read()


class MarkdownParser:
    """Parse markdown structure"""

    def parse(self, md_text):
        """Parse markdown into structured data"""
        lines = md_text.split('\n')

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


class DocumentToVideoConverter:
    """Convert document structure to video scenes"""

    def __init__(self, target_duration=60, max_scenes=6):
        self.target_duration = target_duration
        self.max_scenes = max_scenes

    def convert_to_scenes(self, structure):
        """Convert document structure to video scenes"""
        scenes = []

        # Scene 1: Title (from document title)
        if structure['title']:
            title_scene = {
                'type': 'title',
                'id': 'scene_01_title',
                'title': structure['title'],
                'subtitle': self._generate_subtitle(structure),
                'key_message': self._extract_intro_message(structure)
            }
            scenes.append(title_scene)

        # Convert sections to scenes
        sections_to_use = structure['sections'][:self.max_scenes - 2]  # Reserve for title + outro

        for i, section in enumerate(sections_to_use, 2):
            scene = self._section_to_scene(section, i)
            if scene:
                scenes.append(scene)

        # Final scene: Outro
        outro_scene = {
            'type': 'outro',
            'id': f'scene_{len(scenes)+1:02d}_outro',
            'main_text': self._generate_outro_message(structure),
            'sub_text': 'See Documentation',
            'key_message': self._extract_conclusion(structure)
        }
        scenes.append(outro_scene)

        return scenes

    def _generate_subtitle(self, structure):
        """Generate subtitle from first section or intro"""
        if structure['sections']:
            first_text = structure['sections'][0].get('text', '')
            # Extract first sentence
            sentences = re.split(r'[.!?]', first_text)
            if sentences and sentences[0]:
                return sentences[0].strip()[:50]

        return "Complete Guide"

    def _extract_intro_message(self, structure):
        """Extract introduction message"""
        if structure['sections']:
            first_section = structure['sections'][0]
            text = first_section.get('text', '')
            # Summarize first paragraph
            if text:
                words = text.split()[:15]
                return ' '.join(words)

        return f"Master {structure['title']}"

    def _section_to_scene(self, section, scene_num):
        """Convert section to appropriate scene type"""
        heading = section['heading']
        has_code = len(section.get('code_blocks', [])) > 0
        has_lists = len(section.get('lists', [])) > 0

        if has_code:
            # Command scene
            commands = self._extract_commands(section['code_blocks'])
            key_points = self._extract_key_points(section['text'])

            return {
                'type': 'command',
                'id': f'scene_{scene_num:02d}_{self._slugify(heading)}',
                'header': heading,
                'description': self._summarize_text(section['text'], max_words=8),
                'topic': self._extract_topic(section['text']),
                'commands': commands,
                'key_points': key_points[:3]  # Top 3 points
            }

        elif has_lists:
            # List scene
            items = []
            for lst in section['lists']:
                for item in lst[:5]:  # Max 5 items
                    # Check if item has description (colon or dash separator)
                    if ':' in item or ' - ' in item:
                        parts = re.split(r':\s*|-\s*', item, 1)
                        if len(parts) == 2:
                            items.append({
                                'title': parts[0].strip(),
                                'description': parts[1].strip()[:50]
                            })
                        else:
                            items.append(item)
                    else:
                        items.append(item)

            return {
                'type': 'list',
                'id': f'scene_{scene_num:02d}_{self._slugify(heading)}',
                'header': heading,
                'description': self._summarize_text(section['text'], max_words=6),
                'topic': self._extract_topic(section['text']),
                'items': items
            }

        else:
            # Text-only section - convert to command scene with key points
            key_points = self._extract_key_points(section['text'])

            if key_points:
                return {
                    'type': 'list',
                    'id': f'scene_{scene_num:02d}_{self._slugify(heading)}',
                    'header': heading,
                    'description': self._summarize_text(section['text'], max_words=8),
                    'topic': self._extract_topic(section['text']),
                    'items': key_points[:5]
                }

        return None

    def _extract_commands(self, code_blocks):
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

    def _extract_key_points(self, text):
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

    def _extract_topic(self, text):
        """Extract main topic from text"""
        if not text:
            return ""

        # First sentence is usually the topic
        sentences = re.split(r'[.!?]', text)
        if sentences and sentences[0]:
            topic = sentences[0].strip()
            # Keep it short
            words = topic.split()[:12]
            return ' '.join(words)

        return ""

    def _summarize_text(self, text, max_words=8):
        """Summarize text to max_words"""
        if not text:
            return ""

        words = text.split()[:max_words]
        return ' '.join(words)

    def _generate_outro_message(self, structure):
        """Generate outro closing message"""
        title = structure['title']
        if 'guide' in title.lower() or 'tutorial' in title.lower():
            return "Start Using This Today"
        elif 'feature' in title.lower():
            return "Try These Features"
        else:
            return "Learn More"

    def _extract_conclusion(self, structure):
        """Extract conclusion message"""
        if structure['sections']:
            last_section = structure['sections'][-1]
            text = last_section.get('text', '')
            if text:
                words = text.split()[:15]
                return ' '.join(words)

        return "Everything you need to get started"

    def _slugify(self, text):
        """Convert text to slug"""
        slug = text.lower()
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[\s_-]+', '_', slug)
        slug = slug[:30]  # Max 30 chars
        return slug


def generate_yaml_from_document(doc_source, accent_color='blue', voice='male', target_duration=60):
    """Main function: Document → YAML"""

    logger.info(f"\n{'='*80}")
    logger.info("DOCUMENT TO VIDEO CONVERTER")
    logger.info(f"{'='*80}\n")

    # Read document
    doc_text = read_document(doc_source)
    logger.info(f"✓ Document loaded ({len(doc_text)} characters)\n")

    # Parse structure
    parser = MarkdownParser()
    structure = parser.parse(doc_text)
    logger.info(f"✓ Parsed structure:")
    logger.info(f"  Title: {structure['title']}")
    logger.info(f"  Sections: {len(structure['sections'])}\n")

    # Convert to scenes
    converter = DocumentToVideoConverter(target_duration=target_duration)
    scenes = converter.convert_to_scenes(structure)
    logger.info(f"✓ Generated {len(scenes)} scenes\n")

    # Create YAML structure
    video_id = converter._slugify(structure['title'] or 'generated_video')

    yaml_data = {
        'video': {
            'id': video_id,
            'title': structure['title'] or 'Generated Video',
            'description': f'Video generated from document',
            'accent_color': accent_color,
            'voice': voice,
            'version': 'v2.0',
            'target_duration': target_duration,
            'source': os.path.basename(doc_source) if not doc_source.startswith('http') else doc_source
        },
        'scenes': scenes
    }

    # Save YAML
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    yaml_file = f"inputs/{video_id}_from_doc_{timestamp}.yaml"

    os.makedirs('inputs', exist_ok=True)

    import yaml
    with open(yaml_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    logger.info(f"{'='*80}")
    logger.info("YAML GENERATED")
    logger.info(f"{'='*80}\n")
    logger.info(f"Output: {yaml_file}\n")
    logger.info("Next steps:")
    logger.info(f"  1. Review YAML: cat {yaml_file}")
    logger.info(f"  2. Edit if needed: nano {yaml_file}")
    logger.info(f"  3. Generate script: python generate_script_from_yaml.py {yaml_file}")
    logger.info(f"\n{'='*80}\n")

    return yaml_file


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Convert document to video script')
    parser.add_argument('document', help='Path to document or URL')
    parser.add_argument('--accent-color', default='blue', choices=['orange', 'blue', 'purple', 'green', 'pink', 'cyan'])
    parser.add_argument('--voice', default='male', choices=['male', 'female'])
    parser.add_argument('--duration', type=int, default=60, help='Target duration in seconds')
    parser.add_argument('--max-scenes', type=int, default=6, help='Maximum number of scenes')

    args = parser.parse_args()

    try:
        yaml_file = generate_yaml_from_document(
            args.document,
            accent_color=args.accent_color,
            voice=args.voice,
            target_duration=args.duration
        )
    except Exception as e:
        logger.error(f"\n❌ Error: {e}\n")
        sys.exit(1)
