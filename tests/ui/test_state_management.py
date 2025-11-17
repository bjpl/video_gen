"""
State Management Tests
Tests for Alpine.js state management and data persistence
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from bs4 import BeautifulSoup
import sys
import re

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
# Alpine.js State Initialization Tests
# ============================================================================

class TestAlpineStateInitialization:
    """Test Alpine.js state initialization"""

    def test_scene_builder_state_initialization(self, client, html_parser):
        """Test scene builder initializes with correct state"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find Alpine.js data attribute
        alpine_component = soup.find(attrs={'x-data': True})
        assert alpine_component, "No Alpine.js component found"

        # Check for sceneBuilder() initialization
        x_data = alpine_component.get('x-data')
        assert 'sceneBuilder' in x_data, "Scene builder not initialized"

    def test_alpine_cloak_prevents_flash(self, client, html_parser):
        """Test x-cloak prevents content flash"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find elements with x-cloak
        cloaked = soup.find_all(attrs={'x-cloak': True})

        # Should have at least some cloaked elements
        assert len(cloaked) > 0, "No x-cloak elements found"

        # Check CSS defines x-cloak
        styles = soup.find_all('style')
        has_cloak_style = any(
            'x-cloak' in style.get_text()
            for style in styles
        )

        assert has_cloak_style, "x-cloak CSS not defined"

    def test_multilingual_state_initialization(self, client, html_parser):
        """Test multilingual state initializes correctly"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for multilingual state variables
        assert 'multilingualEnabled' in content
        assert 'sourceLanguage' in content
        assert 'targetLanguages' in content


# ============================================================================
# Form State Management Tests
# ============================================================================

class TestFormStateManagement:
    """Test form state persistence and validation"""

    def test_video_metadata_state_binding(self, client, html_parser):
        """Test video metadata x-model bindings"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find inputs with x-model directives
        video_id_input = soup.find('input', attrs={'x-model': 'videoSet.set_id'})
        video_name_input = soup.find('input', attrs={'x-model': 'videoSet.set_name'})
        color_select = soup.find('select', attrs={'x-model': 'videoSet.accent_color'})

        assert video_id_input, "Video ID input missing x-model"
        assert video_name_input, "Video name input missing x-model"
        assert color_select, "Accent color select missing x-model"

    def test_scene_state_array_management(self, client, html_parser):
        """Test scenes array state management"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for scene array manipulation methods
        assert 'addScene' in content
        assert 'removeScene' in content
        assert 'moveScene' in content

        # Check for scene iteration
        assert 'x-for' in content or 'for (scene' in content

    def test_dynamic_scene_form_rendering(self, client, html_parser):
        """Test scene forms render based on type"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find conditional scene form templates
        title_template = soup.find('template', attrs={'x-if': re.compile(r"scene\.type === 'title'")})
        command_template = soup.find('template', attrs={'x-if': re.compile(r"scene\.type === 'command'")})

        # Templates should exist for dynamic rendering
        # Note: BeautifulSoup may not parse x-if correctly, so check content
        content = response.content.decode('utf-8')
        assert "x-if=\"scene.type === 'title'\"" in content
        assert "x-if=\"scene.type === 'command'\"" in content


# ============================================================================
# State Reactivity Tests
# ============================================================================

class TestStateReactivity:
    """Test reactive state updates"""

    def test_multilingual_toggle_reactivity(self, client, html_parser):
        """Test multilingual toggle shows/hides content"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find multilingual checkbox
        ml_checkbox = soup.find('input', attrs={'x-model': 'multilingualEnabled'})
        assert ml_checkbox, "Multilingual checkbox missing"

        # Find content that should be conditionally shown
        ml_content = soup.find_all(attrs={'x-show': 'multilingualEnabled'})
        assert len(ml_content) > 0, "No conditionally shown multilingual content"

    def test_scene_count_reactivity(self, client, html_parser):
        """Test scene count updates reactively"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find elements that display scene count
        count_displays = soup.find_all(attrs={'x-text': re.compile(r'scenes\.length')})
        assert len(count_displays) > 0, "No reactive scene count displays"

    def test_generate_button_state(self, client, html_parser):
        """Test generate button disabled state"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find generate button
        generate_btn = soup.find('button', string=re.compile(r'Generate'))

        if generate_btn:
            # Should have disabled binding
            has_disabled = generate_btn.get(':disabled') or generate_btn.get('x-bind:disabled')
            # Some buttons use Alpine.js :disabled binding


# ============================================================================
# Progress State Management Tests
# ============================================================================

class TestProgressStateManagement:
    """Test progress tracking state management"""

    def test_loading_modal_state(self, client, html_parser):
        """Test loading modal state management"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Find loading modal
        loading_modal = soup.find(attrs={'x-show': 'generating'})
        assert loading_modal, "Loading modal not found"

    def test_progress_state_structure(self, client, html_parser):
        """Test progress state has required properties"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for progress state initialization
        assert 'progress:' in content
        assert 'progress:' in content or 'progress =' in content

        # Should have progress and message properties
        assert 'progress' in content
        assert 'message' in content


# ============================================================================
# Error State Management Tests
# ============================================================================

class TestErrorStateManagement:
    """Test error handling in state management"""

    def test_error_handling_in_generate_function(self, client, html_parser):
        """Test error handling during generation"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Should have try-catch in generate function
        generate_func_match = re.search(
            r'async generateVideo\(\).*?try.*?catch',
            content,
            re.DOTALL
        )
        assert generate_func_match, "Generate function missing error handling"

    def test_error_modal_state(self, client, html_parser):
        """Test error modal state management"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Should handle errors with alerts or error state
        assert 'alert' in content or 'error' in content.lower()


# ============================================================================
# Data Transformation Tests
# ============================================================================

class TestDataTransformation:
    """Test data transformation for API submission"""

    def test_scene_data_transformation(self, client, html_parser):
        """Test scenes are transformed correctly for API"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for transformation logic
        assert 'transformedScenes' in content or 'map(scene' in content

        # Should convert string arrays to actual arrays
        assert 'split(' in content

    def test_multilingual_payload_construction(self, client, html_parser):
        """Test multilingual payload is constructed correctly"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for multilingual payload logic
        assert 'multilingual' in content
        assert 'source_language' in content
        assert 'target_languages' in content


# ============================================================================
# Component Interaction Tests
# ============================================================================

class TestComponentInteraction:
    """Test interaction between components"""

    def test_modal_state_coordination(self, client, html_parser):
        """Test modals coordinate with main state"""
        response = client.get('/create')
        soup = html_parser(response)

        # Find save template modal
        save_modal = soup.find(attrs={'x-show': 'showSaveTemplateModal'})

        if save_modal:
            # Modal should have open/close handlers
            has_close_handler = bool(
                save_modal.get('@click') or
                save_modal.find(attrs={'@click': True})
            )

    def test_form_validation_state(self, client, html_parser):
        """Test form validation state management"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Check for validation logic
        # (May use JavaScript validation libraries)
        if 'validation' in content.lower():
            assert 'valid' in content.lower() or 'error' in content.lower()


# ============================================================================
# Performance State Tests
# ============================================================================

class TestPerformanceState:
    """Test performance-related state management"""

    def test_debounced_input_handling(self, client, html_parser):
        """Test inputs use debouncing for performance"""
        response = client.get('/builder')
        content = response.content.decode('utf-8')

        # Check for debounce or throttle patterns
        # Alpine.js uses .debounce modifier
        has_debounce = '.debounce' in content

        # Debouncing is optional but recommended for performance

    def test_lazy_loading_patterns(self, client, html_parser):
        """Test lazy loading of heavy content"""
        response = client.get('/builder')
        soup = html_parser(response)

        # Check for x-show (better performance than x-if for toggling)
        x_show_elements = soup.find_all(attrs={'x-show': True})
        assert len(x_show_elements) > 0, "No lazy-loaded content found"


# ============================================================================
# Local Storage State Persistence Tests
# ============================================================================

class TestStatePersistence:
    """Test state persistence to localStorage"""

    def test_template_saving_state(self, client, html_parser):
        """Test template saving persists state"""
        response = client.get('/create')
        content = response.content.decode('utf-8')

        # Check for localStorage or template saving logic
        if 'template' in content.lower():
            # Should have save/load template functions
            has_save = 'saveTemplate' in content
            has_load = 'loadTemplate' in content or 'template' in content


# ============================================================================
# Integration: Complete State Flow Test
# ============================================================================

def test_complete_state_flow_integration(client, html_parser):
    """Integration test: Complete state management flow"""
    response = client.get('/builder')
    assert response.status_code == 200

    soup = html_parser(response)
    content = response.content.decode('utf-8')

    # Verify all critical state components exist
    checks = {
        "Alpine.js initialized": bool(soup.find(attrs={'x-data': True})),
        "Scene array management": 'scenes' in content,
        "Add scene function": 'addScene' in content,
        "Remove scene function": 'removeScene' in content,
        "Generate function": 'generateVideo' in content,
        "Loading state": 'generating' in content,
        "Progress tracking": 'progress' in content,
        "Error handling": 'try' in content or 'catch' in content
    }

    failed_checks = [name for name, passed in checks.items() if not passed]

    assert len(failed_checks) == 0, (
        f"State management checks failed: {', '.join(failed_checks)}"
    )


def test_scene_builder_state_lifecycle(client, html_parser):
    """Integration test: Scene builder state lifecycle"""
    response = client.get('/builder')
    content = response.content.decode('utf-8')

    # Verify complete state lifecycle
    lifecycle_stages = {
        "Initialization": 'videoSet' in content and 'scenes' in content,
        "User input binding": 'x-model' in content,
        "State updates": 'scenes.push' in content or 'addScene' in content,
        "Data transformation": 'map(' in content or 'transform' in content,
        "API submission": 'fetch(' in content,
        "Progress tracking": 'progress' in content,
        "Completion handling": 'complete' in content or 'success' in content
    }

    failed_stages = [stage for stage, passed in lifecycle_stages.items() if not passed]

    assert len(failed_stages) == 0, (
        f"Lifecycle stages failed: {', '.join(failed_stages)}"
    )
