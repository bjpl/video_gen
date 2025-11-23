"""Content parser for extracting structure from content.

This module analyzes content and extracts structured information that can
be used to generate video scenes and narratives.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json

from ..shared.models import SceneConfig as Scene
from ..shared.config import config


@dataclass
class ParseResult:
    """Result from content parsing.

    Attributes:
        success: Whether parsing succeeded
        scenes: Extracted scenes
        metadata: Parsing metadata (topics, keywords, etc.)
        error: Error message if parsing failed
    """

    success: bool
    scenes: List[Scene] = None
    metadata: Dict[str, Any] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.scenes is None:
            self.scenes = []
        if self.metadata is None:
            self.metadata = {}


class ContentParser:
    """Parser for extracting structured content.

    This class analyzes content (text, documents, transcripts) and extracts
    structured information like topics, sections, and key concepts.
    """

    def __init__(self):
        """Initialize the content parser."""
        # Use global config singleton
        pass  # Config is imported as module-level singleton
        self.anthropic_available = False

        # Try to import and initialize Anthropic client
        try:
            from anthropic import AsyncAnthropic
            api_key = config.get_api_key("anthropic")
            if api_key:
                self.client = AsyncAnthropic(api_key=api_key)
                self.anthropic_available = True
        except ImportError:
            pass

    async def parse(
        self,
        content: str,
        content_type: str = "text",
        **kwargs
    ) -> ParseResult:
        """Parse content into structured scenes.

        Args:
            content: Content to parse
            content_type: Type of content (text, markdown, etc.)
            **kwargs: Additional parsing parameters

        Returns:
            ParseResult with extracted scenes
        """
        try:
            # If AI is not available, return basic success without AI parsing
            if not self.anthropic_available:
                return ParseResult(
                    success=True,
                    metadata={"method": "basic", "ai_enabled": False}
                )

            # Use AI to analyze content
            scene_type = kwargs.get('scene_type', 'general')

            # Create AI prompt for content analysis
            prompt = self._create_analysis_prompt(content, scene_type)

            # Call Claude API
            response = await self.client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )

            # Extract analysis from response
            analysis_text = response.content[0].text
            analysis = self._parse_analysis(analysis_text)

            return ParseResult(
                success=True,
                metadata={
                    "method": "ai",
                    "ai_enabled": True,
                    "topics": analysis.get("topics", []),
                    "keywords": analysis.get("keywords", []),
                    "complexity": analysis.get("complexity", "medium")
                }
            )

        except Exception as e:
            return ParseResult(
                success=False,
                error=f"Content parsing failed: {e}"
            )

    def _create_analysis_prompt(self, content: str, scene_type: str) -> str:
        """Create prompt for AI content analysis."""
        return f"""You are analyzing content for an educational video about technical topics.

Content to analyze:
{content[:1000]}

Scene type: {scene_type}

Extract the following in JSON format:
{{
    "topics": ["main topic 1", "main topic 2"],  // Core concepts covered
    "keywords": ["technical term 1", "term 2"],  // Important technical terms
    "complexity": "simple|medium|complex",  // How complex is this content?
    "engagement_level": "low|medium|high",  // How engaging/interesting?
    "key_takeaways": ["takeaway 1", "takeaway 2"],  // What should viewers remember?
    "suggested_visuals": ["visual idea 1", "visual idea 2"]  // What to show on screen
}}

Focus on: technical accuracy, educational value, clarity for learners."""

    def _parse_analysis(self, analysis_text: str) -> Dict[str, Any]:
        """Parse AI analysis response."""
        try:
            # Try to extract JSON from response
            start = analysis_text.find('{')
            end = analysis_text.rfind('}') + 1
            if start != -1 and end > start:
                json_str = analysis_text[start:end]
                return json.loads(json_str)
        except:
            pass

        # Return default analysis if parsing fails
        return {
            "topics": [],
            "keywords": [],
            "complexity": "medium"
        }

    async def extract_topics(self, content: str) -> List[str]:
        """Extract main topics from content.

        Args:
            content: Content to analyze

        Returns:
            List of identified topics
        """
        if not self.anthropic_available:
            return []

        try:
            result = await self.parse(content)
            return result.metadata.get("topics", [])
        except:
            return []

    async def extract_keywords(self, content: str) -> List[str]:
        """Extract keywords from content.

        Args:
            content: Content to analyze

        Returns:
            List of keywords
        """
        if not self.anthropic_available:
            return []

        try:
            result = await self.parse(content)
            return result.metadata.get("keywords", [])
        except:
            return []

    async def split_into_sections(
        self,
        content: str,
        max_section_length: int = 500
    ) -> List[Dict[str, Any]]:
        """Split content into logical sections.

        Args:
            content: Content to split
            max_section_length: Maximum section length

        Returns:
            List of sections with metadata
        """
        # Basic section splitting by paragraphs
        paragraphs = content.split('\n\n')
        sections = []

        current_section = ""
        for para in paragraphs:
            if len(current_section) + len(para) > max_section_length and current_section:
                sections.append({
                    "text": current_section.strip(),
                    "length": len(current_section)
                })
                current_section = para
            else:
                current_section += "\n\n" + para if current_section else para

        if current_section:
            sections.append({
                "text": current_section.strip(),
                "length": len(current_section)
            })

        return sections
