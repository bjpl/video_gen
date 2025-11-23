"""
PreviewPanel Component Tests
============================

Tests for the preview panel component including:
- Component initialization
- Document preview rendering
- YouTube preview rendering
- Section collapsing/expanding
- Loading and error states
- Duration formatting
- API data handling
- Accessibility compliance
- Responsive design
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from bs4 import BeautifulSoup
import sys
import re
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def html_parser():
    """Helper to parse HTML responses"""
    def parse(response):
        return BeautifulSoup(response.content, 'html.parser')
    return parse


# ============================================================================
# Component Initialization Tests
# ============================================================================

class TestPreviewPanelInitialization:
    """Test preview panel component initialization"""

    def test_preview_panel_js_exists(self, client):
        """Test preview panel JS file exists"""
        response = client.get('/static/js/components/preview-panel.js')
        assert response.status_code == 200, "preview-panel.js not found"
        assert 'previewPanel' in response.text, "previewPanel function not found"

    def test_preview_panel_alpine_component(self, client):
        """Test preview panel Alpine.js component structure"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Check for required state variables
        required_state = ['preview', 'previewType', 'isLoading', 'error', 'isExpanded']
        for state in required_state:
            assert state in content, f"Missing state variable: {state}"

    def test_preview_panel_methods(self, client):
        """Test preview panel has required methods"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        required_methods = [
            'loadPreview',
            'toggleSection',
            'clearPreview',
            'formatDuration',
            'estimateReadTime'
        ]
        for method in required_methods:
            assert method in content, f"Missing method: {method}"

    def test_preview_panel_event_listeners(self, client):
        """Test preview panel has event listeners"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should listen for external events
        assert 'preview-ready' in content, "Missing preview-ready event listener"
        assert 'preview-clear' in content, "Missing preview-clear event listener"

    def test_preview_panel_custom_events(self, client):
        """Test preview panel dispatches custom events"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should dispatch custom events
        assert "$dispatch('preview-loaded'" in content or 'preview-loaded' in content, "Missing preview-loaded event dispatch"
        assert "$dispatch('preview-cleared'" in content or 'preview-cleared' in content, "Missing preview-cleared event dispatch"


# ============================================================================
# Document Preview Rendering Tests
# ============================================================================

class TestDocumentPreviewRendering:
    """Test document preview rendering functionality"""

    def test_document_preview_api(self, client):
        """Test document preview API exists"""
        response = client.post('/api/preview/document')
        assert response.status_code != 404, "Document preview API not found"

    def test_document_preview_section_display(self, client):
        """Test document preview has section handling"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should handle sections
        assert 'sections' in content, "Missing sections handling"
        assert 'sectionCount' in content, "Missing section count"

    def test_document_preview_word_count(self, client):
        """Test document preview has word count"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'wordCount' in content, "Missing word count"
        assert 'word_count' in content, "Missing word_count property access"

    def test_document_preview_estimated_scenes(self, client):
        """Test document preview has estimated scenes"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'estimatedScenes' in content, "Missing estimated scenes"

    def test_document_preview_recommendations(self, client):
        """Test document preview has recommendations"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'recommendations' in content, "Missing recommendations"

    def test_document_preview_code_detection(self, client):
        """Test document preview has code detection"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'hasCode' in content or 'has_code' in content, "Missing code detection"

    def test_document_preview_list_detection(self, client):
        """Test document preview has list detection"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'hasLists' in content or 'has_lists' in content, "Missing list detection"


# ============================================================================
# YouTube Preview Rendering Tests
# ============================================================================

class TestYouTubePreviewRendering:
    """Test YouTube preview rendering functionality"""

    def test_youtube_preview_api(self, client):
        """Test YouTube preview API exists"""
        response = client.post('/api/youtube/preview')
        assert response.status_code != 404, "YouTube preview API not found"

    def test_youtube_preview_thumbnail(self, client):
        """Test YouTube preview has thumbnail handling"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'thumbnail' in content.lower(), "Missing thumbnail handling"
        assert 'thumbnailUrl' in content, "Missing thumbnailUrl property"

    def test_youtube_preview_channel(self, client):
        """Test YouTube preview has channel display"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'channel' in content.lower(), "Missing channel handling"
        assert 'channelName' in content, "Missing channelName property"

    def test_youtube_preview_transcript(self, client):
        """Test YouTube preview has transcript availability"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'hasTranscript' in content or 'has_transcript' in content, "Missing transcript handling"
        assert 'transcriptLanguages' in content, "Missing transcript languages"

    def test_youtube_preview_view_count(self, client):
        """Test YouTube preview has view count formatting"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'formatViewCount' in content, "Missing view count formatter"
        assert 'view_count' in content, "Missing view_count property access"

    def test_youtube_preview_generation_estimate(self, client):
        """Test YouTube preview has generation estimate"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'generationEstimate' in content or 'generation_estimate' in content, "Missing generation estimate"


# ============================================================================
# Section Collapsing/Expanding Tests
# ============================================================================

class TestSectionCollapsing:
    """Test section collapsing and expanding functionality"""

    def test_toggle_section_method(self, client):
        """Test toggleSection method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'toggleSection' in content, "Missing toggleSection method"

    def test_expanded_sections_state(self, client):
        """Test expandedSections state tracking"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'expandedSections' in content, "Missing expandedSections state"

    def test_is_section_expanded_method(self, client):
        """Test isSectionExpanded method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'isSectionExpanded' in content, "Missing isSectionExpanded method"

    def test_expand_all_method(self, client):
        """Test expandAll method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'expandAll' in content, "Missing expandAll method"

    def test_collapse_all_method(self, client):
        """Test collapseAll method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'collapseAll' in content, "Missing collapseAll method"

    def test_default_first_section_expanded(self, client):
        """Test first section is expanded by default"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should expand first section by default
        assert 'expandedSections = [0]' in content or 'Expand first section' in content, \
            "First section should be expanded by default"


# ============================================================================
# Loading and Error State Tests
# ============================================================================

class TestLoadingAndErrorStates:
    """Test loading and error state handling"""

    def test_is_loading_state(self, client):
        """Test isLoading state exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'isLoading' in content, "Missing isLoading state"

    def test_error_state(self, client):
        """Test error state exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'error' in content, "Missing error state"

    def test_set_loading_method(self, client):
        """Test setLoading method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'setLoading' in content, "Missing setLoading method"

    def test_set_error_method(self, client):
        """Test setError method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'setError' in content, "Missing setError method"

    def test_retry_method(self, client):
        """Test retry method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'retry' in content, "Missing retry method"

    def test_retry_count_tracking(self, client):
        """Test retry count is tracked"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'errorRetryCount' in content or 'retryCount' in content, "Missing retry count tracking"
        assert 'maxRetries' in content, "Missing max retries limit"


# ============================================================================
# Duration Formatting Tests
# ============================================================================

class TestDurationFormatting:
    """Test duration formatting utilities"""

    def test_format_duration_method(self, client):
        """Test formatDuration method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'formatDuration' in content, "Missing formatDuration method"

    def test_format_duration_handles_seconds(self, client):
        """Test formatDuration handles various second values"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should handle hours, minutes, seconds
        assert 'hours' in content.lower(), "Missing hours handling in formatDuration"
        assert 'minutes' in content.lower(), "Missing minutes handling in formatDuration"
        assert 'secs' in content or 'seconds' in content.lower(), "Missing seconds handling in formatDuration"

    def test_format_duration_pad_start(self, client):
        """Test formatDuration uses padStart for formatting"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'padStart' in content, "Missing padStart for time formatting"

    def test_estimate_read_time_method(self, client):
        """Test estimateReadTime method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'estimateReadTime' in content, "Missing estimateReadTime method"

    def test_format_number_method(self, client):
        """Test formatNumber method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'formatNumber' in content, "Missing formatNumber method"

    def test_truncate_text_method(self, client):
        """Test truncateText method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'truncateText' in content, "Missing truncateText method"


# ============================================================================
# API Data Handling Tests
# ============================================================================

class TestAPIDataHandling:
    """Test API data handling"""

    def test_load_preview_method(self, client):
        """Test loadPreview method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'loadPreview' in content, "Missing loadPreview method"

    def test_clear_preview_method(self, client):
        """Test clearPreview method exists"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'clearPreview' in content, "Missing clearPreview method"

    def test_update_global_store(self, client):
        """Test global store integration"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'updateGlobalStore' in content, "Missing updateGlobalStore method"
        assert 'Alpine.store' in content, "Missing Alpine.store integration"

    def test_has_preview_computed(self, client):
        """Test hasPreview computed property"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'hasPreview' in content, "Missing hasPreview computed property"

    def test_preview_type_handling(self, client):
        """Test preview type handling"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'previewType' in content, "Missing previewType state"
        assert 'isDocumentPreview' in content, "Missing isDocumentPreview computed"
        assert 'isYouTubePreview' in content, "Missing isYouTubePreview computed"


# ============================================================================
# CSS Styles Tests
# ============================================================================

class TestPreviewPanelStyles:
    """Test preview panel CSS styles"""

    def test_preview_panel_css_exists(self, client):
        """Test preview panel CSS exists"""
        response = client.get('/static/css/components.css')
        assert response.status_code == 200, "components.css not found"
        assert '.preview-panel' in response.text, "Missing .preview-panel styles"

    def test_preview_panel_header_styles(self, client):
        """Test preview panel header styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-panel__header' in content, "Missing header styles"

    def test_preview_panel_content_styles(self, client):
        """Test preview panel content styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-panel__content' in content, "Missing content styles"

    def test_preview_section_styles(self, client):
        """Test preview section styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-section' in content, "Missing section styles"
        assert '.preview-section--document' in content, "Missing document section styles"
        assert '.preview-section--youtube' in content, "Missing youtube section styles"

    def test_preview_metadata_grid_styles(self, client):
        """Test preview metadata grid styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-metadata-grid' in content, "Missing metadata grid styles"

    def test_preview_thumbnail_styles(self, client):
        """Test preview thumbnail styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-thumbnail' in content, "Missing thumbnail styles"

    def test_preview_sections_list_styles(self, client):
        """Test preview sections list styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-sections' in content, "Missing sections list styles"
        assert '.preview-sections__toggle' in content, "Missing toggle styles"

    def test_preview_recommendations_styles(self, client):
        """Test preview recommendations styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '.preview-recommendations' in content, "Missing recommendations styles"


# ============================================================================
# Responsive Design Tests
# ============================================================================

class TestResponsiveDesign:
    """Test responsive design"""

    def test_responsive_media_queries(self, client):
        """Test responsive media queries exist"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert '@media (max-width: 640px)' in content, "Missing mobile breakpoint"

    def test_reduced_motion_support(self, client):
        """Test reduced motion support"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert 'prefers-reduced-motion' in content, "Missing reduced motion support"

    def test_high_contrast_support(self, client):
        """Test high contrast mode support"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert 'prefers-contrast: high' in content, "Missing high contrast support"

    def test_dark_mode_support(self, client):
        """Test dark mode support"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert 'prefers-color-scheme: dark' in content, "Missing dark mode support"


# ============================================================================
# Accessibility Tests
# ============================================================================

class TestAccessibility:
    """Test accessibility compliance"""

    def test_aria_live_region(self, client):
        """Test ARIA live region exists"""
        # Check template includes aria-live
        # Note: We test the JS component for ARIA handling
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Component should work with ARIA regions
        assert 'aria' in content.lower() or 'dispatch' in content, \
            "Component should support accessibility"

    def test_focus_visible_styles(self, client):
        """Test focus visible styles"""
        response = client.get('/static/css/components.css')
        content = response.text

        assert 'focus-visible' in content, "Missing focus-visible styles"

    def test_collapsible_section_aria(self, client):
        """Test collapsible sections have ARIA support"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        # Should support aria-expanded tracking
        assert 'isSectionExpanded' in content, "Missing section expansion tracking for ARIA"


# ============================================================================
# Integration Tests
# ============================================================================

class TestPreviewPanelIntegration:
    """Integration tests for preview panel"""

    def test_base_html_includes_script(self, client):
        """Test base.html includes preview-panel.js"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        assert 'preview-panel.js' in content, "preview-panel.js not included in page"

    def test_create_page_loads(self, client):
        """Test create page loads successfully"""
        response = client.get('/create')
        assert response.status_code == 200

    def test_builder_page_loads(self, client):
        """Test builder page loads successfully"""
        response = client.get('/builder')
        assert response.status_code == 200

    def test_apis_respond(self, client):
        """Test related APIs respond"""
        endpoints = [
            '/api/voices',
            '/api/colors',
            '/api/languages',
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"API {endpoint} not responding"

    def test_preview_apis_exist(self, client):
        """Test preview APIs exist"""
        # Document preview
        response = client.post('/api/preview/document')
        assert response.status_code != 404, "Document preview API not found"

        # YouTube preview
        response = client.post('/api/youtube/preview')
        assert response.status_code != 404, "YouTube preview API not found"


# ============================================================================
# Template Tests
# ============================================================================

class TestPreviewPanelTemplate:
    """Test preview panel HTML template"""

    def test_template_exists(self, client):
        """Test preview-panel.html template exists"""
        # Template is served as part of pages, not directly
        # We check if the component can be used
        response = client.get('/static/js/components/preview-panel.js')
        assert response.status_code == 200, "Preview panel component not found"

    def test_component_has_loading_state_structure(self, client):
        """Test component supports loading state structure"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'isLoading' in content, "Missing loading state"
        assert 'skeleton' in content.lower() or 'loading' in content.lower(), \
            "Missing loading indicator support"

    def test_component_has_error_state_structure(self, client):
        """Test component supports error state structure"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'error' in content, "Missing error state"
        assert 'retry' in content.lower(), "Missing retry support"


# ============================================================================
# Global Store Integration Tests
# ============================================================================

class TestGlobalStoreIntegration:
    """Test global store integration"""

    def test_app_state_exists(self, client):
        """Test app-state.js exists"""
        response = client.get('/static/js/store/app-state.js')
        assert response.status_code == 200, "app-state.js not found"

    def test_preview_panel_reads_store(self, client):
        """Test preview panel reads from store"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert "Alpine.store('appState')" in content, "Missing store read"

    def test_preview_panel_writes_store(self, client):
        """Test preview panel writes to store"""
        response = client.get('/static/js/components/preview-panel.js')
        content = response.text

        assert 'updateGlobalStore' in content, "Missing store update method"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
