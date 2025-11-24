"""Intelligent content splitting for multi-video generation.

This module provides multiple strategies for splitting documents into
logical sections, working across all file types (text, markdown, PDF, etc.).

Strategies:
1. AI-Powered: Uses Claude/OpenAI to intelligently detect natural section boundaries
2. Structural: Uses markdown headers, paragraphs, or other structural markers
3. Length-Based: Splits by word/character count with smart boundary detection
4. Manual: User provides split points explicitly

The splitter automatically selects the best strategy based on:
- Content structure (markdown vs plain text)
- Document length
- User preferences
- AI API availability
"""

from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import re
import logging

logger = logging.getLogger(__name__)


class SplitStrategy(str, Enum):
    """Available splitting strategies."""
    AUTO = "auto"              # Automatically select best strategy
    AI_INTELLIGENT = "ai"      # AI-powered semantic splitting
    MARKDOWN_HEADERS = "headers"  # Split by H1/H2 headers
    PARAGRAPH = "paragraph"    # Split by paragraph boundaries
    LENGTH = "length"          # Split by word/character count
    SENTENCE = "sentence"      # Split by sentences (natural breaks)
    MANUAL = "manual"          # User-provided split points


@dataclass
class ContentSection:
    """A section of split content."""
    title: str
    content: str
    start_index: int
    end_index: int
    word_count: int
    metadata: Dict[str, Any]


@dataclass
class SplitResult:
    """Result of content splitting operation."""
    sections: List[ContentSection]
    strategy_used: SplitStrategy
    confidence: float  # 0.0-1.0, how confident we are in the split quality
    metadata: Dict[str, Any]


class ContentSplitter:
    """Intelligent content splitter with multiple strategies."""

    def __init__(self, ai_api_key: Optional[str] = None, use_ai: bool = True):
        """Initialize content splitter.

        Args:
            ai_api_key: Optional API key for AI splitting
            use_ai: Whether to enable AI-powered splitting
        """
        self.ai_api_key = ai_api_key
        self.use_ai = use_ai and ai_api_key is not None

        if self.use_ai:
            logger.info("AI-powered splitting enabled")
        else:
            logger.info("Using rule-based splitting only")

    async def split(
        self,
        content: str,
        num_sections: int,
        strategy: SplitStrategy = SplitStrategy.AUTO,
        min_words_per_section: int = 50,
        max_words_per_section: int = 500,
        **kwargs
    ) -> SplitResult:
        """Split content into sections.

        Args:
            content: Content to split
            num_sections: Desired number of sections
            strategy: Splitting strategy to use
            min_words_per_section: Minimum words per section
            max_words_per_section: Maximum words per section
            **kwargs: Additional strategy-specific parameters

        Returns:
            SplitResult with sections and metadata
        """
        # Auto-select strategy if requested
        if strategy == SplitStrategy.AUTO:
            strategy = self._select_best_strategy(content, num_sections)
            logger.info(f"Auto-selected strategy: {strategy}")

        # Execute the chosen strategy
        if strategy == SplitStrategy.AI_INTELLIGENT and self.use_ai:
            return await self._split_with_ai(content, num_sections, **kwargs)
        elif strategy == SplitStrategy.MARKDOWN_HEADERS:
            return self._split_by_headers(content, num_sections)
        elif strategy == SplitStrategy.PARAGRAPH:
            return self._split_by_paragraphs(content, num_sections)
        elif strategy == SplitStrategy.LENGTH:
            return self._split_by_length(content, num_sections, min_words_per_section, max_words_per_section)
        elif strategy == SplitStrategy.SENTENCE:
            return self._split_by_sentences(content, num_sections)
        elif strategy == SplitStrategy.MANUAL:
            return self._split_manually(content, **kwargs)
        else:
            # Fallback to length-based
            logger.warning(f"Strategy {strategy} not available, falling back to length-based")
            return self._split_by_length(content, num_sections, min_words_per_section, max_words_per_section)

    def _select_best_strategy(self, content: str, num_sections: int) -> SplitStrategy:
        """Automatically select the best splitting strategy.

        Selection logic:
        1. If markdown with headers -> MARKDOWN_HEADERS
        2. If AI available and content > 500 words -> AI_INTELLIGENT
        3. If clear paragraph structure -> PARAGRAPH
        4. Otherwise -> LENGTH with sentence boundaries
        """
        word_count = len(content.split())

        # Check for markdown headers
        h1_count = len(re.findall(r'^# .+$', content, re.MULTILINE))
        h2_count = len(re.findall(r'^## .+$', content, re.MULTILINE))
        total_headers = h1_count + h2_count

        # If we have enough headers for the requested sections, use them
        if total_headers >= num_sections:
            return SplitStrategy.MARKDOWN_HEADERS

        # For longer content with AI available, use intelligent splitting
        if self.use_ai and word_count > 500:
            return SplitStrategy.AI_INTELLIGENT

        # Check for clear paragraph structure (double newlines)
        paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
        if len(paragraphs) >= num_sections * 2:  # At least 2 paragraphs per section
            return SplitStrategy.PARAGRAPH

        # Default to sentence-aware length splitting
        return SplitStrategy.SENTENCE

    async def _split_with_ai(
        self,
        content: str,
        num_sections: int,
        **kwargs
    ) -> SplitResult:
        """Use AI to intelligently split content into semantic sections.

        The AI analyzes the content and identifies natural topic boundaries,
        creating sections that flow logically and maintain context.
        """
        try:
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=self.ai_api_key)

            # Construct prompt for section detection
            prompt = f"""Analyze this document and split it into exactly {num_sections} logical sections.

Document:
{content}

Requirements:
1. Identify natural topic boundaries and transitions
2. Each section should cover a distinct theme or concept
3. Maintain context and flow between sections
4. Aim for relatively balanced section lengths
5. Suggest a clear title for each section

Respond with JSON in this format:
{{
  "sections": [
    {{
      "title": "Section title",
      "start_marker": "First few words to identify start...",
      "end_marker": "Last few words to identify end...",
      "reasoning": "Why this is a logical section boundary"
    }}
  ]
}}"""

            response = await client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                temperature=0.3,  # Lower temp for more consistent structure
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse AI response
            import json
            response_text = response.content[0].text

            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'```json\n(.*?)\n```', response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1)

            ai_result = json.loads(response_text)

            # Convert AI sections to ContentSection objects
            sections = self._convert_ai_sections_to_content(content, ai_result['sections'])

            return SplitResult(
                sections=sections,
                strategy_used=SplitStrategy.AI_INTELLIGENT,
                confidence=0.9,  # High confidence for AI-powered splits
                metadata={
                    "ai_model": "claude-sonnet-4",
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                }
            )

        except Exception as e:
            logger.warning(f"AI splitting failed: {e}, falling back to sentence-based")
            return self._split_by_sentences(content, num_sections)

    def _split_by_headers(self, content: str, num_sections: int) -> SplitResult:
        """Split by markdown headers (H1, H2)."""
        sections = []

        # Find all headers with their positions
        header_pattern = r'^(#{1,2})\s+(.+)$'
        matches = list(re.finditer(header_pattern, content, re.MULTILINE))

        if not matches:
            # No headers found, fallback to paragraph splitting
            return self._split_by_paragraphs(content, num_sections)

        # Split content by headers
        for i, match in enumerate(matches[:num_sections]):
            start_pos = match.start()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(content)

            section_content = content[start_pos:end_pos].strip()
            title = match.group(2).strip()

            sections.append(ContentSection(
                title=title,
                content=section_content,
                start_index=start_pos,
                end_index=end_pos,
                word_count=len(section_content.split()),
                metadata={"header_level": len(match.group(1))}
            ))

        # If we don't have enough sections, combine or split as needed
        sections = self._adjust_section_count(sections, content, num_sections)

        return SplitResult(
            sections=sections,
            strategy_used=SplitStrategy.MARKDOWN_HEADERS,
            confidence=0.8,
            metadata={"headers_found": len(matches)}
        )

    def _split_by_paragraphs(self, content: str, num_sections: int) -> SplitResult:
        """Split by paragraph boundaries (double newlines)."""
        paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]

        if len(paragraphs) < num_sections:
            # Not enough paragraphs, fallback to length-based
            return self._split_by_length(content, num_sections)

        # Group paragraphs into sections
        paras_per_section = len(paragraphs) // num_sections
        sections = []

        for i in range(num_sections):
            start_idx = i * paras_per_section
            end_idx = start_idx + paras_per_section if i < num_sections - 1 else len(paragraphs)

            section_paras = paragraphs[start_idx:end_idx]
            section_content = '\n\n'.join(section_paras)

            # Generate title from first sentence
            first_sentence = section_paras[0].split('.')[0].strip()
            title = first_sentence[:50] + "..." if len(first_sentence) > 50 else first_sentence

            sections.append(ContentSection(
                title=f"Section {i + 1}: {title}",
                content=section_content,
                start_index=0,  # Approximate
                end_index=len(section_content),
                word_count=len(section_content.split()),
                metadata={"paragraph_count": len(section_paras)}
            ))

        return SplitResult(
            sections=sections,
            strategy_used=SplitStrategy.PARAGRAPH,
            confidence=0.7,
            metadata={"total_paragraphs": len(paragraphs)}
        )

    def _split_by_sentences(self, content: str, num_sections: int) -> SplitResult:
        """Split by sentences, maintaining natural breaks."""
        # Simple sentence detection (can be enhanced)
        sentences = re.split(r'(?<=[.!?])\s+', content)

        if len(sentences) < num_sections:
            # Very short content, just split by length
            return self._split_by_length(content, num_sections)

        sentences_per_section = len(sentences) // num_sections
        sections = []

        for i in range(num_sections):
            start_idx = i * sentences_per_section
            end_idx = start_idx + sentences_per_section if i < num_sections - 1 else len(sentences)

            section_sentences = sentences[start_idx:end_idx]
            section_content = ' '.join(section_sentences)

            # Title from first few words
            title = ' '.join(section_content.split()[:8]) + "..."

            sections.append(ContentSection(
                title=f"Part {i + 1}",
                content=section_content,
                start_index=0,
                end_index=len(section_content),
                word_count=len(section_content.split()),
                metadata={"sentence_count": len(section_sentences)}
            ))

        return SplitResult(
            sections=sections,
            strategy_used=SplitStrategy.SENTENCE,
            confidence=0.6,
            metadata={"total_sentences": len(sentences)}
        )

    def _split_by_length(
        self,
        content: str,
        num_sections: int,
        min_words: int = 50,
        max_words: int = 500
    ) -> SplitResult:
        """Split by approximate equal length, respecting sentence boundaries."""
        words = content.split()
        total_words = len(words)
        target_words_per_section = total_words // num_sections

        sections = []
        current_pos = 0

        for i in range(num_sections):
            # Calculate target end position
            if i == num_sections - 1:
                # Last section gets remaining content
                section_words = words[current_pos:]
            else:
                target_end = current_pos + target_words_per_section
                # Find nearest sentence boundary (. ! ?)
                section_words = words[current_pos:target_end]

                # Look ahead for sentence end
                for j in range(min(20, len(words) - target_end)):
                    if words[target_end + j].endswith(('.', '!', '?')):
                        section_words = words[current_pos:target_end + j + 1]
                        break

            section_content = ' '.join(section_words)
            title = ' '.join(section_words[:8]) + "..."

            sections.append(ContentSection(
                title=f"Section {i + 1}",
                content=section_content,
                start_index=current_pos,
                end_index=current_pos + len(section_words),
                word_count=len(section_words),
                metadata={"target_words": target_words_per_section}
            ))

            current_pos += len(section_words)

        return SplitResult(
            sections=sections,
            strategy_used=SplitStrategy.LENGTH,
            confidence=0.5,
            metadata={"total_words": total_words}
        )

    def _split_manually(self, content: str, split_points: List[int] = None, **kwargs) -> SplitResult:
        """Split at user-specified points."""
        if not split_points:
            raise ValueError("Manual splitting requires split_points parameter")

        sections = []
        split_points = [0] + sorted(split_points) + [len(content)]

        for i in range(len(split_points) - 1):
            start = split_points[i]
            end = split_points[i + 1]
            section_content = content[start:end].strip()

            sections.append(ContentSection(
                title=f"Section {i + 1}",
                content=section_content,
                start_index=start,
                end_index=end,
                word_count=len(section_content.split()),
                metadata={"manual_split": True}
            ))

        return SplitResult(
            sections=sections,
            strategy_used=SplitStrategy.MANUAL,
            confidence=1.0,  # User knows best!
            metadata={"split_points": split_points}
        )

    def _convert_ai_sections_to_content(
        self,
        full_content: str,
        ai_sections: List[Dict[str, Any]]
    ) -> List[ContentSection]:
        """Convert AI-identified sections to ContentSection objects."""
        sections = []

        for i, ai_section in enumerate(ai_sections):
            # Find start and end positions using markers
            start_marker = ai_section.get('start_marker', '')
            end_marker = ai_section.get('end_marker', '')

            # Simple search for markers in content
            start_pos = full_content.find(start_marker) if start_marker else 0
            end_pos = full_content.find(end_marker) + len(end_marker) if end_marker else len(full_content)

            if start_pos == -1:
                start_pos = 0
            if end_pos == -1 or end_pos <= start_pos:
                end_pos = len(full_content)

            section_content = full_content[start_pos:end_pos].strip()

            sections.append(ContentSection(
                title=ai_section.get('title', f'Section {i + 1}'),
                content=section_content,
                start_index=start_pos,
                end_index=end_pos,
                word_count=len(section_content.split()),
                metadata={
                    "ai_reasoning": ai_section.get('reasoning', ''),
                    "ai_generated": True
                }
            ))

        return sections

    def _adjust_section_count(
        self,
        sections: List[ContentSection],
        full_content: str,
        target_count: int
    ) -> List[ContentSection]:
        """Adjust number of sections to match target count."""
        if len(sections) == target_count:
            return sections

        if len(sections) < target_count:
            # Need to split some sections further
            # Split the longest sections
            while len(sections) < target_count:
                longest_idx = max(range(len(sections)), key=lambda i: sections[i].word_count)
                longest = sections[longest_idx]

                # Split this section in half
                mid_point = len(longest.content) // 2
                # Find nearest sentence boundary
                for offset in range(0, min(100, len(longest.content) - mid_point)):
                    if longest.content[mid_point + offset] in '.!?':
                        mid_point += offset + 1
                        break

                first_half = longest.content[:mid_point].strip()
                second_half = longest.content[mid_point:].strip()

                sections[longest_idx] = ContentSection(
                    title=longest.title + " (Part 1)",
                    content=first_half,
                    start_index=longest.start_index,
                    end_index=longest.start_index + mid_point,
                    word_count=len(first_half.split()),
                    metadata={**longest.metadata, "split": True}
                )

                sections.insert(longest_idx + 1, ContentSection(
                    title=longest.title + " (Part 2)",
                    content=second_half,
                    start_index=longest.start_index + mid_point,
                    end_index=longest.end_index,
                    word_count=len(second_half.split()),
                    metadata={**longest.metadata, "split": True}
                ))

        elif len(sections) > target_count:
            # Need to merge some sections
            # Merge the shortest adjacent sections
            while len(sections) > target_count:
                # Find smallest section
                smallest_idx = min(range(len(sections) - 1), key=lambda i: sections[i].word_count)

                # Merge with next section
                merged_content = sections[smallest_idx].content + "\n\n" + sections[smallest_idx + 1].content
                sections[smallest_idx] = ContentSection(
                    title=sections[smallest_idx].title,
                    content=merged_content,
                    start_index=sections[smallest_idx].start_index,
                    end_index=sections[smallest_idx + 1].end_index,
                    word_count=len(merged_content.split()),
                    metadata={**sections[smallest_idx].metadata, "merged": True}
                )

                sections.pop(smallest_idx + 1)

        return sections
