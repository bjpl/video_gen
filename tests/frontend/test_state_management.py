"""
Frontend State Management Tests

Tests for the enhanced state management system including:
- State initialization
- State persistence to localStorage
- State restoration from localStorage
- State validation
- Event bus pub/sub
- API client methods
- Error handling
- Cache functionality
"""

import pytest
from playwright.sync_api import Page, expect


class TestStateInitialization:
    """Tests for state store initialization."""

    def test_store_exists_after_page_load(self, page: Page, base_url: str):
        """Verify Alpine store is created after page load."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("() => !!Alpine.store('appState')")
        assert result is True

    def test_store_has_required_namespaces(self, page: Page, base_url: str):
        """Verify all required state namespaces exist."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        namespaces = page.evaluate("""() => {
            const store = Alpine.store('appState');
            return {
                hasInput: !!store.input,
                hasPreview: !!store.preview,
                hasVideoConfig: !!store.videoConfig,
                hasLanguages: !!store.languages,
                hasVoices: !!store.voices,
                hasProgress: !!store.progress,
                hasValidation: !!store.validation,
                hasUi: !!store.ui
            };
        }""")

        assert namespaces['hasInput'] is True
        assert namespaces['hasPreview'] is True
        assert namespaces['hasVideoConfig'] is True
        assert namespaces['hasLanguages'] is True
        assert namespaces['hasVoices'] is True
        assert namespaces['hasProgress'] is True
        assert namespaces['hasValidation'] is True
        assert namespaces['hasUi'] is True

    def test_store_default_values(self, page: Page, base_url: str):
        """Verify default state values are correct."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        defaults = page.evaluate("""() => {
            const store = Alpine.store('appState');
            return {
                currentStep: store.currentStep,
                inputType: store.input.type,
                selectedLanguages: store.languages.selected,
                isProcessing: store.progress.isProcessing,
                useAiNarration: store.videoConfig.useAiNarration
            };
        }""")

        assert defaults['currentStep'] == 1
        assert defaults['inputType'] == 'document'
        assert 'en' in defaults['selectedLanguages']
        assert defaults['isProcessing'] is False
        assert defaults['useAiNarration'] is True


class TestStatePersistence:
    """Tests for state persistence to localStorage."""

    def test_save_to_storage(self, page: Page, base_url: str):
        """Verify state is saved to localStorage."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        # Modify state and save
        page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.currentStep = 2;
            store.selectedInputMethod = 'youtube';
            store.saveToStorage();
        }""")

        # Check localStorage
        stored = page.evaluate("""() => {
            const raw = localStorage.getItem('vg_state') || localStorage.getItem('appState');
            return raw ? JSON.parse(raw) : null;
        }""")

        assert stored is not None
        assert stored.get('currentStep') == 2 or stored.get('value', {}).get('currentStep') == 2

    def test_load_from_storage(self, page: Page, base_url: str):
        """Verify state is restored from localStorage."""
        page.goto(f"{base_url}/create")

        # Pre-populate localStorage
        page.evaluate("""() => {
            const state = {
                currentStep: 3,
                selectedInputMethod: 'document',
                videoConfig: { title: 'Test Video', duration: 180 },
                _version: '2.0.0',
                _savedAt: Date.now()
            };
            localStorage.setItem('appState', JSON.stringify(state));
        }""")

        # Reload page
        page.reload()
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        # Wait a bit for state to load
        page.wait_for_timeout(500)

        # Check restored values
        restored = page.evaluate("""() => {
            const store = Alpine.store('appState');
            return {
                currentStep: store.currentStep,
                inputMethod: store.selectedInputMethod,
                title: store.videoConfig.title,
                duration: store.videoConfig.duration
            };
        }""")

        assert restored['currentStep'] == 3
        assert restored['inputMethod'] == 'document'
        assert restored['title'] == 'Test Video'
        assert restored['duration'] == 180

    def test_clear_storage(self, page: Page, base_url: str):
        """Verify storage can be cleared."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        # Save something first
        page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.currentStep = 2;
            store.saveToStorage();
        }""")

        # Clear storage
        page.evaluate("""() => {
            Alpine.store('appState').clearStorage();
        }""")

        # Check localStorage is cleared
        stored = page.evaluate("""() => {
            return localStorage.getItem('vg_state') || localStorage.getItem('appState');
        }""")

        assert stored is None


class TestStateValidation:
    """Tests for state validation."""

    def test_validate_empty_languages(self, page: Page, base_url: str):
        """Validation should fail with no languages selected."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.languages.selected = [];
            return store.validateState();
        }""")

        assert result is False

    def test_validate_invalid_duration(self, page: Page, base_url: str):
        """Validation should fail with invalid duration."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.videoConfig.duration = 5; // Too short
            return store.validateState();
        }""")

        assert result is False

    def test_validate_valid_state(self, page: Page, base_url: str):
        """Validation should pass with valid state."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.languages.selected = ['en'];
            store.videoConfig.duration = 120;
            store.selectedInputMethod = 'document';
            return store.validateState();
        }""")

        assert result is True


class TestEventBus:
    """Tests for event bus pub/sub."""

    def test_event_bus_exists(self, page: Page, base_url: str):
        """Verify event bus is created."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.eventBus")

        exists = page.evaluate("() => !!window.eventBus")
        assert exists is True

    def test_event_emit_and_receive(self, page: Page, base_url: str):
        """Test event emission and subscription."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.eventBus")

        result = page.evaluate("""() => {
            return new Promise(resolve => {
                window.eventBus.on('test:event', (data) => {
                    resolve(data);
                });
                window.eventBus.emit('test:event', { message: 'hello' });
            });
        }""")

        assert result['message'] == 'hello'

    def test_event_once(self, page: Page, base_url: str):
        """Test once subscription fires only once."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.eventBus")

        result = page.evaluate("""() => {
            let count = 0;
            window.eventBus.once('test:once', () => count++);
            window.eventBus.emit('test:once', {});
            window.eventBus.emit('test:once', {});
            window.eventBus.emit('test:once', {});
            return count;
        }""")

        assert result == 1

    def test_event_unsubscribe(self, page: Page, base_url: str):
        """Test unsubscribing from events."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.eventBus")

        result = page.evaluate("""() => {
            let count = 0;
            const handler = () => count++;
            window.eventBus.on('test:unsub', handler);
            window.eventBus.emit('test:unsub', {});
            window.eventBus.off('test:unsub', handler);
            window.eventBus.emit('test:unsub', {});
            return count;
        }""")

        assert result == 1


class TestAPIClient:
    """Tests for API client."""

    def test_api_client_exists(self, page: Page, base_url: str):
        """Verify API client is created."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.api")

        exists = page.evaluate("() => !!window.api")
        assert exists is True

    def test_api_client_has_methods(self, page: Page, base_url: str):
        """Verify API client has required methods."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.api")

        methods = page.evaluate("""() => ({
            hasDocument: typeof window.api.document === 'object',
            hasYoutube: typeof window.api.youtube === 'object',
            hasLanguages: typeof window.api.languages === 'object',
            hasTasks: typeof window.api.tasks === 'object',
            hasHealth: typeof window.api.health === 'object'
        })""")

        assert methods['hasDocument'] is True
        assert methods['hasYoutube'] is True
        assert methods['hasLanguages'] is True
        assert methods['hasTasks'] is True
        assert methods['hasHealth'] is True

    def test_api_error_class(self, page: Page, base_url: str):
        """Verify APIError class exists and works."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.APIError")

        result = page.evaluate("""() => {
            const error = new APIError('Test error', 400, { field: 'test' });
            return {
                name: error.name,
                message: error.message,
                status: error.status,
                isValidationError: error.isValidationError,
                isServerError: error.isServerError
            };
        }""")

        assert result['name'] == 'APIError'
        assert result['message'] == 'Test error'
        assert result['status'] == 400
        assert result['isValidationError'] is True
        assert result['isServerError'] is False


class TestErrorHandler:
    """Tests for error handler."""

    def test_error_handler_exists(self, page: Page, base_url: str):
        """Verify error handler is created."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.errorHandler")

        exists = page.evaluate("() => !!window.errorHandler")
        assert exists is True

    def test_handle_error(self, page: Page, base_url: str):
        """Test error handling."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.errorHandler")

        result = page.evaluate("""() => {
            const error = new Error('Test error');
            const handled = window.errorHandler.handle(error, {
                component: 'TestComponent',
                showToast: false
            });
            return {
                hasId: !!handled.id,
                hasTimestamp: !!handled.timestamp,
                hasCategory: !!handled.category
            };
        }""")

        assert result['hasId'] is True
        assert result['hasTimestamp'] is True
        assert result['hasCategory'] is True


class TestStorageManager:
    """Tests for storage manager."""

    def test_storage_manager_exists(self, page: Page, base_url: str):
        """Verify storage manager is created."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.storage")

        exists = page.evaluate("() => !!window.storage")
        assert exists is True

    def test_storage_set_and_get(self, page: Page, base_url: str):
        """Test storage set and get operations."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.storage")

        result = page.evaluate("""() => {
            window.storage.set('test_key', { foo: 'bar' });
            return window.storage.get('test_key');
        }""")

        assert result['foo'] == 'bar'

    def test_storage_ttl(self, page: Page, base_url: str):
        """Test storage TTL expiration."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.storage")

        result = page.evaluate("""() => {
            // Set with 1ms TTL
            window.storage.set('ttl_test', 'value', 1);
            // Wait 10ms
            return new Promise(resolve => {
                setTimeout(() => {
                    resolve(window.storage.get('ttl_test', 'default'));
                }, 10);
            });
        }""")

        assert result == 'default'

    def test_storage_has(self, page: Page, base_url: str):
        """Test storage has operation."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.storage")

        result = page.evaluate("""() => {
            window.storage.set('has_test', 'value');
            return {
                exists: window.storage.has('has_test'),
                notExists: window.storage.has('nonexistent_key')
            };
        }""")

        assert result['exists'] is True
        assert result['notExists'] is False


class TestLanguageManagement:
    """Tests for language selection state management."""

    def test_select_language(self, page: Page, base_url: str):
        """Test language selection."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.selectLanguage('es');
            return store.languages.selected;
        }""")

        assert 'es' in result
        assert 'en' in result

    def test_deselect_language(self, page: Page, base_url: str):
        """Test language deselection."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.selectLanguage('es');
            store.selectLanguage('fr');
            store.deselectLanguage('es');
            return store.languages.selected;
        }""")

        assert 'es' not in result
        assert 'en' in result
        assert 'fr' in result

    def test_cannot_deselect_last_language(self, page: Page, base_url: str):
        """Test that last language cannot be deselected."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.languages.selected = ['en'];
            store.toggleLanguage('en'); // Should not remove last language
            return store.languages.selected;
        }""")

        assert 'en' in result
        assert len(result) >= 1


class TestProgressManagement:
    """Tests for progress state management."""

    def test_start_progress(self, page: Page, base_url: str):
        """Test starting progress tracking."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.startProgress('test-task-123');
            return {
                isProcessing: store.progress.isProcessing,
                taskId: store.progress.taskId,
                currentStage: store.progress.currentStage,
                progress: store.progress.progress
            };
        }""")

        assert result['isProcessing'] is True
        assert result['taskId'] == 'test-task-123'
        assert result['currentStage'] == 'parsing'
        assert result['progress'] == 0

    def test_update_progress(self, page: Page, base_url: str):
        """Test updating progress."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.startProgress('task-456');
            store.updateProgress({ stage: 'generating', progress: 50 });
            return {
                currentStage: store.progress.currentStage,
                progress: store.progress.progress
            };
        }""")

        assert result['currentStage'] == 'generating'
        assert result['progress'] == 50

    def test_complete_progress(self, page: Page, base_url: str):
        """Test completing progress."""
        page.goto(f"{base_url}/create")
        page.wait_for_function("window.Alpine && Alpine.store('appState')")

        result = page.evaluate("""() => {
            const store = Alpine.store('appState');
            store.startProgress('task-789');
            store.completeProgress({ videoUrl: '/output/video.mp4' });
            return {
                isProcessing: store.progress.isProcessing,
                progress: store.progress.progress,
                result: store.progress.result
            };
        }""")

        assert result['isProcessing'] is False
        assert result['progress'] == 100
        assert result['result']['videoUrl'] == '/output/video.mp4'


# Pytest fixtures
@pytest.fixture
def base_url():
    """Return the base URL for the test server."""
    return "http://localhost:8000"


@pytest.fixture(scope="function")
def page(browser):
    """Create a new page for each test."""
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()
