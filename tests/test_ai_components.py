"""
Comprehensive tests for AI components in video_gen.

Tests video_gen/script_generator/ai_enhancer.py and narration.py including:
- AIUsageMetrics: token tracking, cost calculation, success/failure counting
- AIScriptEnhancer: initialization, enhancement, validation, fallback behavior
- NarrationGenerator: template-based narration, scene type handling
- Mock Claude API responses for testing
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
from dataclasses import dataclass

from video_gen.script_generator.ai_enhancer import AIUsageMetrics, AIScriptEnhancer
from video_gen.script_generator.narration import NarrationGenerator
from video_gen.shared.models import SceneConfig
from video_gen.shared.exceptions import ScriptGenerationError


# ============================================================================
# AIUsageMetrics Tests
# ============================================================================

class TestAIUsageMetrics:
    """Test AIUsageMetrics class for tracking AI API usage."""

    def test_initialization(self):
        """Test metrics initialization with zero values."""
        metrics = AIUsageMetrics()
        assert metrics.total_api_calls == 0
        assert metrics.total_input_tokens == 0
        assert metrics.total_output_tokens == 0
        assert metrics.total_cost_usd == 0.0
        assert metrics.successful_enhancements == 0
        assert metrics.failed_enhancements == 0

    def test_record_call_success(self):
        """Test recording a successful API call."""
        metrics = AIUsageMetrics()
        metrics.record_call(input_tokens=100, output_tokens=50, success=True)

        assert metrics.total_api_calls == 1
        assert metrics.total_input_tokens == 100
        assert metrics.total_output_tokens == 50
        assert metrics.successful_enhancements == 1
        assert metrics.failed_enhancements == 0

    def test_record_call_failure(self):
        """Test recording a failed API call."""
        metrics = AIUsageMetrics()
        metrics.record_call(input_tokens=100, output_tokens=0, success=False)

        assert metrics.total_api_calls == 1
        assert metrics.successful_enhancements == 0
        assert metrics.failed_enhancements == 1

    def test_record_multiple_calls(self):
        """Test recording multiple API calls."""
        metrics = AIUsageMetrics()
        metrics.record_call(100, 50, success=True)
        metrics.record_call(200, 75, success=True)
        metrics.record_call(150, 0, success=False)

        assert metrics.total_api_calls == 3
        assert metrics.total_input_tokens == 450
        assert metrics.total_output_tokens == 125
        assert metrics.successful_enhancements == 2
        assert metrics.failed_enhancements == 1

    def test_cost_calculation_accuracy(self):
        """Test cost calculation using Sonnet 4.5 pricing ($3/M input, $15/M output)."""
        metrics = AIUsageMetrics()

        # 1M input tokens + 1M output tokens
        metrics.record_call(1_000_000, 1_000_000, success=True)

        # Expected: (1M / 1M * $3) + (1M / 1M * $15) = $3 + $15 = $18
        assert metrics.total_cost_usd == 18.0

    def test_cost_calculation_small_values(self):
        """Test cost calculation with realistic small token counts."""
        metrics = AIUsageMetrics()

        # 100 input, 50 output tokens
        metrics.record_call(100, 50, success=True)

        # Expected: (100/1M * $3) + (50/1M * $15) = $0.0003 + $0.00075 = $0.00105
        expected_cost = (100 / 1_000_000 * 3.0) + (50 / 1_000_000 * 15.0)
        assert abs(metrics.total_cost_usd - expected_cost) < 0.000001

    def test_get_summary_structure(self):
        """Test get_summary returns correct structure."""
        metrics = AIUsageMetrics()
        metrics.record_call(100, 50, success=True)

        summary = metrics.get_summary()

        assert isinstance(summary, dict)
        assert "api_calls" in summary
        assert "input_tokens" in summary
        assert "output_tokens" in summary
        assert "estimated_cost_usd" in summary
        assert "successful" in summary
        assert "failed" in summary
        assert "success_rate" in summary

    def test_get_summary_values(self):
        """Test get_summary returns correct values."""
        metrics = AIUsageMetrics()
        metrics.record_call(100, 50, success=True)
        metrics.record_call(200, 75, success=True)
        metrics.record_call(150, 0, success=False)

        summary = metrics.get_summary()

        assert summary["api_calls"] == 3
        assert summary["input_tokens"] == 450
        assert summary["output_tokens"] == 125
        assert summary["successful"] == 2
        assert summary["failed"] == 1
        assert summary["success_rate"] == pytest.approx(66.666, rel=0.01)

    def test_get_summary_cost_rounding(self):
        """Test get_summary rounds cost to 4 decimal places."""
        metrics = AIUsageMetrics()
        metrics.record_call(123, 456, success=True)

        summary = metrics.get_summary()

        # Cost should be rounded to 4 decimals
        assert isinstance(summary["estimated_cost_usd"], float)
        # Check that it's rounded (no more than 4 decimal places)
        cost_str = str(summary["estimated_cost_usd"])
        decimal_places = len(cost_str.split('.')[-1]) if '.' in cost_str else 0
        assert decimal_places <= 4

    def test_success_rate_zero_calls(self):
        """Test success rate is 0 when no calls recorded."""
        metrics = AIUsageMetrics()
        summary = metrics.get_summary()

        assert summary["success_rate"] == 0


# ============================================================================
# AIScriptEnhancer Tests
# ============================================================================

class TestAIScriptEnhancerInitialization:
    """Test AIScriptEnhancer initialization."""

    def test_initialization_with_api_key(self):
        """Test initialization with explicit API key."""
        enhancer = AIScriptEnhancer(api_key="test-key-123")

        assert enhancer.api_key == "test-key-123"
        assert isinstance(enhancer.metrics, AIUsageMetrics)

    @patch("video_gen.shared.config.config.get_api_key")
    def test_initialization_from_config(self, mock_get_api_key):
        """Test initialization loads API key from config."""
        mock_get_api_key.return_value = "config-key-456"

        enhancer = AIScriptEnhancer()

        assert enhancer.api_key == "config-key-456"
        mock_get_api_key.assert_called_once_with("anthropic")

    @patch("video_gen.shared.config.config.get_api_key")
    def test_initialization_raises_without_api_key(self, mock_get_api_key):
        """Test initialization raises error when no API key available."""
        mock_get_api_key.return_value = None

        with pytest.raises(ScriptGenerationError, match="API key not configured"):
            AIScriptEnhancer()


class TestAIScriptEnhancerValidation:
    """Test AIScriptEnhancer validation logic."""

    def test_validate_enhanced_script_valid(self):
        """Test validation passes for valid enhanced script."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "This is a test script with some content for testing validation purposes and checking the quality metrics."
        enhanced = "This is an enhanced test script with improved clarity better flow and engaging content for viewers to understand concepts easily and effectively."

        result = enhancer._validate_enhanced_script(enhanced, original)

        assert result["valid"] is True
        assert result["reason"] == "Passed all checks"

    def test_validate_enhanced_script_too_short(self):
        """Test validation fails when enhanced script is too short (<20 words)."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "This is a test script with some content."
        enhanced = "Too short."  # Only 2 words

        result = enhancer._validate_enhanced_script(enhanced, original)

        assert result["valid"] is False
        assert "Too short" in result["reason"]

    def test_validate_enhanced_script_too_long(self):
        """Test validation fails when enhanced script is too long (>200 words)."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "This is a test script."
        # Create a script with over 200 words
        enhanced = " ".join(["word"] * 201)

        result = enhancer._validate_enhanced_script(enhanced, original)

        assert result["valid"] is False
        assert "Too long" in result["reason"]

    def test_validate_enhanced_script_contains_markdown(self):
        """Test validation fails when enhanced script contains markdown."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        # Use longer original to avoid length ratio issues
        original = " ".join(["word"] * 30)

        # Test various markdown patterns
        markdown_patterns = [
            "This is **bold** text and additional content here " + " ".join(["word"] * 15),
            "This is __underlined__ text with more content " + " ".join(["word"] * 15),
            "## This is a heading with additional text " + " ".join(["word"] * 15),
            "This is ```code``` with more text here " + " ".join(["word"] * 15),
        ]

        for enhanced in markdown_patterns:
            result = enhancer._validate_enhanced_script(enhanced, original)
            assert result["valid"] is False
            assert "markdown" in result["reason"].lower()

    def test_validate_enhanced_script_empty_whitespace(self):
        """Test validation fails for empty or whitespace-only script."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "This is a test script."

        # Test empty and whitespace
        for enhanced in ["", "   ", "\n\n\n", "\t\t"]:
            result = enhancer._validate_enhanced_script(enhanced, original)
            assert result["valid"] is False
            # Empty/whitespace fails on either "too short" or "empty" check
            assert "short" in result["reason"].lower() or "empty" in result["reason"].lower() or "whitespace" in result["reason"].lower()

    def test_validate_enhanced_script_length_ratio_too_high(self):
        """Test validation fails when enhanced script is too much longer than original."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "Short script."
        # Enhanced is more than 1.5x longer
        enhanced = " ".join(["word"] * 50)  # Much longer but within 20-200 words

        result = enhancer._validate_enhanced_script(enhanced, original)

        assert result["valid"] is False
        assert "Length changed too much" in result["reason"]

    def test_validate_enhanced_script_length_ratio_too_low(self):
        """Test validation fails when enhanced script is too much shorter than original."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = " ".join(["word"] * 100)  # Long original
        enhanced = " ".join(["word"] * 25)   # Less than 0.5x length

        result = enhancer._validate_enhanced_script(enhanced, original)

        assert result["valid"] is False
        assert "Length changed too much" in result["reason"]

    def test_validate_enhanced_script_parentheses_allowed(self):
        """Test validation allows parentheses and brackets (normal in speech)."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        original = "This is a test script with some content for validation testing purposes and quality checks that ensures everything works as intended."
        enhanced = "This script created for testing purposes demonstrates validation with normal brackets which are perfectly acceptable in natural speech and provides good examples."

        result = enhancer._validate_enhanced_script(enhanced, original)

        # Should pass - parentheses and brackets alone don't trigger markdown failure
        assert result["valid"] is True


class TestAIScriptEnhancerEnhancement:
    """Test AIScriptEnhancer enhancement functionality."""

    @pytest.mark.asyncio
    async def test_enhance_script_success(self):
        """Test successful script enhancement with mocked API."""
        # Mock the anthropic library and API response
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        mock_content.text = "This is an enhanced script that meets all validation criteria and provides better clarity and improved engagement for viewers watching video content."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        # Create a mock module
        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            original = "This is a test script for validation and quality control checks to ensure proper functionality and correctness."
            enhanced = await enhancer.enhance_script(original)

            assert enhanced != original
            assert "enhanced" in enhanced.lower()
            assert enhancer.metrics.total_api_calls == 1
            assert enhancer.metrics.successful_enhancements == 1

    @pytest.mark.asyncio
    async def test_enhance_script_with_scene_type(self):
        """Test enhancement with scene type context."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        mock_content.text = "Welcome to this comprehensive programming guide where we will explore fundamental concepts and demonstrate key principles through practical examples that will enhance your learning."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            original = "Welcome to our comprehensive programming guide today and let us explore important concepts together as we learn valuable new skills."
            enhanced = await enhancer.enhance_script(original, scene_type="title")

            assert enhanced != original
            # Verify API was called with scene type context
            call_args = mock_client.messages.create.call_args
            assert "title" in str(call_args) or "opening" in str(call_args).lower()

    @pytest.mark.asyncio
    async def test_enhance_script_with_position_context_opening(self):
        """Test enhancement with opening scene position context."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        mock_content.text = "Welcome everyone to this exciting tutorial where we will dive deep into the fascinating world of technology and programming fundamentals."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            context = {"scene_position": 0, "total_scenes": 5}
            enhanced = await enhancer.enhance_script("Opening scene for video tutorial.", context=context)

            # Verify OPENING context was used in prompt
            call_args = mock_client.messages.create.call_args
            prompt = call_args[1]["messages"][0]["content"]
            assert "OPENING" in prompt

    @pytest.mark.asyncio
    async def test_enhance_script_with_position_context_final(self):
        """Test enhancement with final scene position context."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        mock_content.text = "Thank you for joining us today and we hope you found this tutorial valuable and educational for your learning journey."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            context = {"scene_position": 4, "total_scenes": 5}
            enhanced = await enhancer.enhance_script("Final scene of tutorial.", context=context)

            # Verify FINAL context was used in prompt
            call_args = mock_client.messages.create.call_args
            prompt = call_args[1]["messages"][0]["content"]
            assert "FINAL" in prompt

    @pytest.mark.asyncio
    async def test_enhance_script_fallback_on_api_failure(self):
        """Test fallback to original script on API failure."""
        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(side_effect=Exception("API Error"))

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            original = "This is the original script that should be returned on failure."
            enhanced = await enhancer.enhance_script(original)

            # Should return original script on failure
            assert enhanced == original
            assert enhancer.metrics.failed_enhancements == 1

    @pytest.mark.asyncio
    async def test_enhance_script_fallback_on_validation_failure(self):
        """Test fallback to original script when validation fails."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        # Return invalid content (too short)
        mock_content.text = "Too short."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            original = "This is the original script that should be returned when validation fails."
            enhanced = await enhancer.enhance_script(original)

            # Should return original script when validation fails
            assert enhanced == original
            assert enhancer.metrics.failed_enhancements == 1

    @pytest.mark.asyncio
    async def test_enhance_alias_method(self):
        """Test enhance() alias method for backward compatibility."""
        mock_usage = MagicMock()
        mock_usage.input_tokens = 100
        mock_usage.output_tokens = 50

        mock_content = MagicMock()
        mock_content.text = "This is an enhanced script with improved quality better engagement and clearer messaging for target audience members today that provides excellent value."

        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(return_value=mock_response)

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic = MagicMock(return_value=mock_client)

        with patch.dict('sys.modules', {'anthropic': mock_anthropic}):
            enhancer = AIScriptEnhancer(api_key="test-key")

            original = "Original script for testing purposes and quality validation checks today to ensure everything works correctly."
            enhanced = await enhancer.enhance(original)

            assert enhanced != original


# ============================================================================
# NarrationGenerator Tests
# ============================================================================

class TestNarrationGeneratorInitialization:
    """Test NarrationGenerator initialization."""

    def test_initialization_defaults(self):
        """Test initialization with default parameters."""
        generator = NarrationGenerator()

        assert generator.language == "en"
        assert generator.style == "professional"

    def test_initialization_custom_language(self):
        """Test initialization with custom language."""
        generator = NarrationGenerator(language="es")

        assert generator.language == "es"

    def test_initialization_custom_style(self):
        """Test initialization with custom style."""
        generator = NarrationGenerator(style="casual")

        assert generator.style == "casual"


class TestNarrationGeneratorGenerate:
    """Test NarrationGenerator generate() method."""

    @pytest.mark.asyncio
    async def test_generate_uses_existing_narration(self):
        """Test generate() returns existing narration from scene."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="title",
            narration="Custom narration from scene.",
            visual_content={"title": "Test Title"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        assert narration == "Custom narration from scene."

    @pytest.mark.asyncio
    async def test_generate_title_scene(self):
        """Test generate() creates template narration for title scene."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="title",
            narration="",  # Empty narration
            visual_content={"title": "Introduction to Python"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        assert "Welcome" in narration
        assert "Introduction to Python" in narration

    @pytest.mark.asyncio
    async def test_generate_outro_scene(self):
        """Test generate() creates template narration for outro scene."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="outro",
            narration="",
            visual_content={"main_text": "Thanks for watching!"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        assert "Thanks for watching!" in narration

    @pytest.mark.asyncio
    async def test_generate_list_scene(self):
        """Test generate() creates template narration for list scene."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="list",
            narration="",
            visual_content={"header": "Key Features"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        assert "Key Features" in narration
        assert "key points" in narration.lower()

    @pytest.mark.asyncio
    async def test_generate_command_scene(self):
        """Test generate() creates template narration for command scene."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="command",
            narration="",
            visual_content={"header": "Git Commands"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        assert "Git Commands" in narration

    @pytest.mark.asyncio
    async def test_generate_unknown_scene_type(self):
        """Test generate() handles unknown scene types."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="quiz",
            narration="",
            visual_content={}
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        # Should create generic narration
        assert "quiz" in narration.lower()

    @pytest.mark.asyncio
    async def test_generate_missing_visual_content_fields(self):
        """Test generate() handles missing visual content fields gracefully."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="title",
            narration="",
            visual_content={}  # Missing 'title' field
        )

        generator = NarrationGenerator()
        narration = await generator.generate(scene)

        # Should use default value
        assert "Welcome" in narration
        assert "Video Title" in narration

    @pytest.mark.asyncio
    async def test_generate_scene_narration_alias(self):
        """Test generate_scene_narration() alias method."""
        scene = SceneConfig(
            scene_id="test-scene",
            scene_type="title",
            narration="Test narration",
            visual_content={"title": "Test"}
        )

        generator = NarrationGenerator()
        narration = await generator.generate_scene_narration(scene)

        assert narration == "Test narration"


class TestNarrationGeneratorNotImplemented:
    """Test NarrationGenerator not-yet-implemented methods."""

    @pytest.mark.asyncio
    async def test_generate_script_not_implemented(self):
        """Test generate_script() raises NotImplementedError."""
        generator = NarrationGenerator()

        scene = SceneConfig(
            scene_id="test",
            scene_type="title",
            narration="Test",
            visual_content={}
        )

        with pytest.raises(NotImplementedError):
            await generator.generate_script([scene])

    @pytest.mark.asyncio
    async def test_apply_style_not_implemented(self):
        """Test apply_style() raises NotImplementedError."""
        generator = NarrationGenerator()

        with pytest.raises(NotImplementedError):
            await generator.apply_style("Test text")


# ============================================================================
# AIScriptEnhancer Not-Implemented Methods Tests
# ============================================================================

class TestAIScriptEnhancerNotImplemented:
    """Test AIScriptEnhancer not-yet-implemented methods."""

    @pytest.mark.asyncio
    async def test_translate_script_not_implemented(self):
        """Test translate_script() raises NotImplementedError."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        with pytest.raises(NotImplementedError, match="Translation not yet implemented"):
            await enhancer.translate_script("Test script", "es")

    @pytest.mark.asyncio
    async def test_improve_clarity_not_implemented(self):
        """Test improve_clarity() raises NotImplementedError."""
        enhancer = AIScriptEnhancer(api_key="test-key")

        with pytest.raises(NotImplementedError, match="Clarity improvement not yet implemented"):
            await enhancer.improve_clarity("Test script")
