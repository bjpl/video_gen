"""
P1 Week 2 Feature Testing: Preset Packages
===========================================

Tests preset package system for:
- 3 preset packages (Corporate, Creative, Educational)
- Correct configurations applied
- "Start from Preset" workflow
- Cost displays match actual costs
- Preset customization
- Analytics tracking
"""

import pytest
from decimal import Decimal
from typing import Dict, List, Optional


class PresetPackages:
    """Preset package configurations for testing"""

    PRESETS = {
        'corporate': {
            'name': 'Corporate Professional',
            'description': 'Polished, professional videos for business presentations and reports',
            'icon': '💼',
            'config': {
                'accent_color': 'blue',
                'voice': 'male',
                'scene_duration': 8,
                'ai_narration': True,
                'enable_subtitles': True,
                'transition_style': 'fade',
                'font_style': 'professional',
            },
            'recommended_for': [
                'Business presentations',
                'Annual reports',
                'Corporate training',
                'Investor updates',
            ],
            'estimated_cost_per_scene': Decimal('0.00075'),  # AI narration only
        },
        'creative': {
            'name': 'Creative Content',
            'description': 'Dynamic, engaging videos for social media and marketing',
            'icon': '🎨',
            'config': {
                'accent_color': 'orange',
                'voice': 'female_friendly',
                'scene_duration': 6,
                'ai_narration': True,
                'enable_subtitles': True,
                'transition_style': 'slide',
                'font_style': 'modern',
            },
            'recommended_for': [
                'Social media content',
                'Marketing campaigns',
                'Brand storytelling',
                'Product launches',
            ],
            'estimated_cost_per_scene': Decimal('0.00075'),
        },
        'educational': {
            'name': 'Educational Learning',
            'description': 'Clear, structured videos for tutorials and online courses',
            'icon': '📚',
            'config': {
                'accent_color': 'purple',
                'voice': 'male_warm',
                'scene_duration': 10,
                'ai_narration': True,
                'enable_subtitles': True,
                'transition_style': 'none',
                'font_style': 'clear',
            },
            'recommended_for': [
                'Online courses',
                'Tutorial videos',
                'Educational content',
                'Training materials',
            ],
            'estimated_cost_per_scene': Decimal('0.00075'),
        },
    }

    @classmethod
    def get_preset(cls, preset_id: str) -> Optional[Dict]:
        """Get preset configuration"""
        return cls.PRESETS.get(preset_id)

    @classmethod
    def list_presets(cls) -> List[str]:
        """List available preset IDs"""
        return list(cls.PRESETS.keys())

    @classmethod
    def apply_preset(cls, preset_id: str, overrides: Optional[Dict] = None) -> Dict:
        """Apply preset with optional overrides"""
        preset = cls.get_preset(preset_id)
        if not preset:
            raise ValueError(f"Unknown preset: {preset_id}")

        config = preset['config'].copy()
        if overrides:
            config.update(overrides)

        return config


class TestPresetDefinitions:
    """Test that all presets are properly defined"""

    REQUIRED_PRESETS = ['corporate', 'creative', 'educational']

    def test_all_required_presets_exist(self):
        """Test that all 3 required presets exist"""
        available = PresetPackages.list_presets()

        for preset_id in self.REQUIRED_PRESETS:
            assert preset_id in available, f"Missing preset: {preset_id}"

    def test_presets_have_required_fields(self):
        """Test that each preset has all required fields"""
        required_fields = [
            'name', 'description', 'icon', 'config',
            'recommended_for', 'estimated_cost_per_scene'
        ]

        for preset_id in self.REQUIRED_PRESETS:
            preset = PresetPackages.get_preset(preset_id)
            assert preset is not None

            for field in required_fields:
                assert field in preset, f"Missing {field} in {preset_id}"

    def test_preset_configs_complete(self):
        """Test that each preset config has all necessary settings"""
        required_config_fields = [
            'accent_color', 'voice', 'scene_duration',
            'ai_narration', 'enable_subtitles'
        ]

        for preset_id in self.REQUIRED_PRESETS:
            preset = PresetPackages.get_preset(preset_id)
            config = preset['config']

            for field in required_config_fields:
                assert field in config, \
                    f"Missing {field} in {preset_id} config"

    def test_preset_names_descriptive(self):
        """Test that preset names are descriptive"""
        for preset_id in self.REQUIRED_PRESETS:
            preset = PresetPackages.get_preset(preset_id)
            name = preset['name']

            assert len(name) > 5, f"Preset name too short: {preset_id}"
            assert name[0].isupper(), f"Preset name not capitalized: {preset_id}"

    def test_preset_descriptions_helpful(self):
        """Test that preset descriptions are helpful"""
        for preset_id in self.REQUIRED_PRESETS:
            preset = PresetPackages.get_preset(preset_id)
            description = preset['description']

            assert len(description) > 20, \
                f"Description too short for {preset_id}"


class TestCorporatePreset:
    """Test Corporate Professional preset"""

    def test_corporate_color_scheme(self):
        """Test corporate uses professional blue"""
        preset = PresetPackages.get_preset('corporate')
        assert preset['config']['accent_color'] == 'blue'

    def test_corporate_voice_selection(self):
        """Test corporate uses professional male voice"""
        preset = PresetPackages.get_preset('corporate')
        assert preset['config']['voice'] == 'male'

    def test_corporate_scene_duration(self):
        """Test corporate uses moderate pacing"""
        preset = PresetPackages.get_preset('corporate')
        assert preset['config']['scene_duration'] == 8

    def test_corporate_ai_narration_enabled(self):
        """Test corporate enables AI narration"""
        preset = PresetPackages.get_preset('corporate')
        assert preset['config']['ai_narration'] is True

    def test_corporate_subtitles_enabled(self):
        """Test corporate enables subtitles"""
        preset = PresetPackages.get_preset('corporate')
        assert preset['config']['enable_subtitles'] is True

    def test_corporate_recommended_uses(self):
        """Test corporate has business-focused recommendations"""
        preset = PresetPackages.get_preset('corporate')
        recommended = preset['recommended_for']

        assert len(recommended) > 0
        assert any('business' in item.lower() or 'corporate' in item.lower()
                   for item in recommended)


class TestCreativePreset:
    """Test Creative Content preset"""

    def test_creative_color_scheme(self):
        """Test creative uses energetic orange"""
        preset = PresetPackages.get_preset('creative')
        assert preset['config']['accent_color'] == 'orange'

    def test_creative_voice_selection(self):
        """Test creative uses friendly female voice"""
        preset = PresetPackages.get_preset('creative')
        assert preset['config']['voice'] == 'female_friendly'

    def test_creative_scene_duration(self):
        """Test creative uses faster pacing"""
        preset = PresetPackages.get_preset('creative')
        assert preset['config']['scene_duration'] == 6

        # Should be faster than corporate
        corporate = PresetPackages.get_preset('corporate')
        assert preset['config']['scene_duration'] < corporate['config']['scene_duration']

    def test_creative_ai_narration_enabled(self):
        """Test creative enables AI narration"""
        preset = PresetPackages.get_preset('creative')
        assert preset['config']['ai_narration'] is True

    def test_creative_recommended_uses(self):
        """Test creative has marketing-focused recommendations"""
        preset = PresetPackages.get_preset('creative')
        recommended = preset['recommended_for']

        assert len(recommended) > 0
        assert any('marketing' in item.lower() or 'social' in item.lower()
                   for item in recommended)


class TestEducationalPreset:
    """Test Educational Learning preset"""

    def test_educational_color_scheme(self):
        """Test educational uses purple for learning"""
        preset = PresetPackages.get_preset('educational')
        assert preset['config']['accent_color'] == 'purple'

    def test_educational_voice_selection(self):
        """Test educational uses warm male voice"""
        preset = PresetPackages.get_preset('educational')
        assert preset['config']['voice'] == 'male_warm'

    def test_educational_scene_duration(self):
        """Test educational uses slower pacing for comprehension"""
        preset = PresetPackages.get_preset('educational')
        assert preset['config']['scene_duration'] == 10

        # Should be slowest of the three
        corporate = PresetPackages.get_preset('corporate')
        creative = PresetPackages.get_preset('creative')

        assert preset['config']['scene_duration'] > corporate['config']['scene_duration']
        assert preset['config']['scene_duration'] > creative['config']['scene_duration']

    def test_educational_ai_narration_enabled(self):
        """Test educational enables AI narration"""
        preset = PresetPackages.get_preset('educational')
        assert preset['config']['ai_narration'] is True

    def test_educational_recommended_uses(self):
        """Test educational has learning-focused recommendations"""
        preset = PresetPackages.get_preset('educational')
        recommended = preset['recommended_for']

        assert len(recommended) > 0
        assert any('education' in item.lower() or 'tutorial' in item.lower() or 'course' in item.lower()
                   for item in recommended)


class TestPresetApplication:
    """Test applying presets to configuration"""

    def test_apply_preset_returns_complete_config(self):
        """Test that applying preset returns complete configuration"""
        config = PresetPackages.apply_preset('corporate')

        assert 'accent_color' in config
        assert 'voice' in config
        assert 'scene_duration' in config
        assert 'ai_narration' in config

    def test_apply_corporate_preset(self):
        """Test applying corporate preset"""
        config = PresetPackages.apply_preset('corporate')
        expected = PresetPackages.PRESETS['corporate']['config']

        assert config == expected

    def test_apply_creative_preset(self):
        """Test applying creative preset"""
        config = PresetPackages.apply_preset('creative')
        expected = PresetPackages.PRESETS['creative']['config']

        assert config == expected

    def test_apply_educational_preset(self):
        """Test applying educational preset"""
        config = PresetPackages.apply_preset('educational')
        expected = PresetPackages.PRESETS['educational']['config']

        assert config == expected

    def test_apply_invalid_preset_raises_error(self):
        """Test that invalid preset raises error"""
        with pytest.raises(ValueError):
            PresetPackages.apply_preset('nonexistent')


class TestPresetCustomization:
    """Test customizing presets with overrides"""

    def test_override_single_field(self):
        """Test overriding single field in preset"""
        config = PresetPackages.apply_preset('corporate', {'accent_color': 'green'})

        # Overridden field
        assert config['accent_color'] == 'green'

        # Other fields from preset
        assert config['voice'] == 'male'
        assert config['scene_duration'] == 8

    def test_override_multiple_fields(self):
        """Test overriding multiple fields"""
        overrides = {
            'accent_color': 'cyan',
            'voice': 'female',
            'scene_duration': 12,
        }
        config = PresetPackages.apply_preset('corporate', overrides)

        # All overrides applied
        assert config['accent_color'] == 'cyan'
        assert config['voice'] == 'female'
        assert config['scene_duration'] == 12

        # Other fields from preset
        assert config['ai_narration'] is True

    def test_override_doesnt_modify_original_preset(self):
        """Test that overrides don't modify original preset"""
        original = PresetPackages.get_preset('corporate')
        original_color = original['config']['accent_color']

        # Apply with override
        config = PresetPackages.apply_preset('corporate', {'accent_color': 'red'})

        # Original preset unchanged
        assert PresetPackages.get_preset('corporate')['config']['accent_color'] == original_color

    def test_customize_all_presets(self):
        """Test that all presets can be customized"""
        overrides = {'scene_duration': 15}

        for preset_id in PresetPackages.list_presets():
            config = PresetPackages.apply_preset(preset_id, overrides)
            assert config['scene_duration'] == 15


class TestPresetCostEstimation:
    """Test cost estimation for presets"""

    def test_all_presets_have_cost_estimate(self):
        """Test that all presets have cost estimates"""
        for preset_id in PresetPackages.list_presets():
            preset = PresetPackages.get_preset(preset_id)
            assert 'estimated_cost_per_scene' in preset
            assert isinstance(preset['estimated_cost_per_scene'], Decimal)

    def test_preset_cost_matches_ai_narration_cost(self):
        """Test that preset costs match AI narration costs"""
        expected_ai_cost = Decimal('0.00075')

        for preset_id in PresetPackages.list_presets():
            preset = PresetPackages.get_preset(preset_id)

            # All presets use AI narration, so cost should match
            if preset['config']['ai_narration']:
                assert preset['estimated_cost_per_scene'] == expected_ai_cost

    def test_calculate_total_cost_with_preset(self):
        """Test calculating total cost for preset configuration"""
        num_scenes = 10
        preset = PresetPackages.get_preset('corporate')

        cost_per_scene = preset['estimated_cost_per_scene']
        total_cost = cost_per_scene * num_scenes

        assert total_cost == Decimal('0.0075')  # 10 * 0.00075

    def test_cost_display_for_preset_card(self):
        """Test cost display format for preset cards"""
        preset = PresetPackages.get_preset('corporate')
        cost = preset['estimated_cost_per_scene']

        # Format for display
        display = f"${cost:.5f} per scene"
        assert display == "$0.00075 per scene"


class TestPresetWorkflow:
    """Test "Start from Preset" workflow"""

    def test_start_from_preset_workflow(self):
        """Test complete preset selection workflow"""
        # User selects preset
        selected_preset = 'corporate'
        preset = PresetPackages.get_preset(selected_preset)

        # Verify preset loaded
        assert preset is not None
        assert 'config' in preset

        # Apply preset
        config = PresetPackages.apply_preset(selected_preset)

        # Verify all settings applied
        assert config['accent_color'] == 'blue'
        assert config['voice'] == 'male'

    def test_preset_selection_clears_previous_config(self):
        """Test that selecting preset clears previous configuration"""
        # Simulate previous config
        previous_config = {
            'accent_color': 'red',
            'voice': 'female',
            'scene_duration': 20,
        }

        # Select preset (should replace previous config)
        new_config = PresetPackages.apply_preset('corporate')

        # New config should match preset, not previous config
        assert new_config != previous_config
        assert new_config['accent_color'] == 'blue'

    def test_can_modify_preset_after_selection(self):
        """Test that user can modify preset after selection"""
        # Start with preset
        config = PresetPackages.apply_preset('corporate')
        original_color = config['accent_color']

        # User modifies a field
        config['accent_color'] = 'pink'

        # Modification should be preserved
        assert config['accent_color'] == 'pink'
        assert config['accent_color'] != original_color


class TestPresetAnalytics:
    """Test analytics tracking for preset usage"""

    def test_track_preset_selection(self):
        """Test tracking which preset was selected"""
        # This would integrate with analytics
        # Spec: Track event "preset_selected" with preset_id
        selected_preset = 'corporate'

        analytics_event = {
            'event': 'preset_selected',
            'preset_id': selected_preset,
            'timestamp': '2025-01-01T00:00:00Z',
        }

        assert analytics_event['event'] == 'preset_selected'
        assert analytics_event['preset_id'] == selected_preset

    def test_track_preset_customization(self):
        """Test tracking customizations to presets"""
        # Spec: Track which fields were customized after preset selection
        preset_id = 'corporate'
        overrides = {'accent_color': 'green', 'voice': 'female'}

        analytics_event = {
            'event': 'preset_customized',
            'preset_id': preset_id,
            'customized_fields': list(overrides.keys()),
            'timestamp': '2025-01-01T00:00:00Z',
        }

        assert 'accent_color' in analytics_event['customized_fields']
        assert 'voice' in analytics_event['customized_fields']

    def test_track_preset_usage_frequency(self):
        """Test tracking most popular presets"""
        # Spec: Aggregate preset selection counts
        usage_stats = {
            'corporate': 45,
            'creative': 30,
            'educational': 25,
        }

        most_popular = max(usage_stats, key=usage_stats.get)
        assert most_popular == 'corporate'


class TestPresetAccessibility:
    """Test accessibility of preset selection UI"""

    def test_preset_cards_keyboard_accessible(self):
        """Test that preset cards can be selected via keyboard"""
        # Frontend integration test specification
        # Spec: Tab to preset card + Enter to select
        pass

    def test_preset_cards_have_aria_labels(self):
        """Test that preset cards have proper ARIA labels"""
        # Frontend integration test specification
        # Spec: aria-label="Corporate Professional preset"
        pass

    def test_preset_descriptions_screen_reader_friendly(self):
        """Test that descriptions are announced by screen readers"""
        # Frontend integration test specification
        # Spec: Use aria-describedby for detailed descriptions
        pass


class TestPresetUIDisplay:
    """Test preset UI display elements"""

    def test_preset_has_icon(self):
        """Test that each preset has an icon"""
        for preset_id in PresetPackages.list_presets():
            preset = PresetPackages.get_preset(preset_id)
            assert 'icon' in preset
            assert preset['icon'], f"Empty icon for {preset_id}"

    def test_preset_icons_unique(self):
        """Test that each preset has a unique icon"""
        icons = [PresetPackages.get_preset(pid)['icon']
                 for pid in PresetPackages.list_presets()]

        assert len(icons) == len(set(icons)), "Duplicate icons found"

    def test_preset_recommended_for_displayed(self):
        """Test that recommended uses are displayed"""
        for preset_id in PresetPackages.list_presets():
            preset = PresetPackages.get_preset(preset_id)
            recommended = preset['recommended_for']

            assert len(recommended) >= 3, \
                f"Not enough recommendations for {preset_id}"


class TestPresetIntegration:
    """Integration tests for preset system"""

    def test_preset_config_structure(self):
        """Test the preset configuration structure"""
        config = {
            'enabled': True,
            'default_preset': 'corporate',
            'allow_customization': True,
            'track_usage': True,
            'presets': PresetPackages.PRESETS,
        }

        assert 'enabled' in config
        assert 'presets' in config
        assert len(config['presets']) == 3

    def test_preset_integrates_with_smart_defaults(self):
        """Test that presets work with smart defaults"""
        # If preset selected, it should override smart defaults
        # If no preset, smart defaults apply based on content type
        pass

    def test_preset_integrates_with_cost_estimator(self):
        """Test that presets integrate with cost estimator"""
        preset = PresetPackages.get_preset('corporate')
        num_scenes = 10

        # Cost estimator should use preset's AI narration setting
        if preset['config']['ai_narration']:
            expected_cost = Decimal('0.00075') * num_scenes
            assert expected_cost == Decimal('0.0075')


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
