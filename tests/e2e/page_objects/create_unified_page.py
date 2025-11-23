"""
CreateUnifiedPage Page Object Model
====================================

Page object model for the unified create page with methods for:
- Document upload
- YouTube URL entry
- Language selection
- Voice selection
- Video configuration
- Generation and progress tracking
"""

from typing import List, Optional, Dict, Any
import time

# Try to import Selenium, but don't fail if not installed
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    # Create mock classes for type hints
    class By:
        ID = "id"
        CSS_SELECTOR = "css selector"
        XPATH = "xpath"
        CLASS_NAME = "class name"


class CreateUnifiedPage:
    """
    Page Object Model for the unified video creation page.

    This class provides methods to interact with all components
    of the create-unified.html page for E2E testing.
    """

    # Selectors
    SELECTORS = {
        # Main page elements
        "page_container": "[x-data]",
        "step_indicator": ".step-indicator, [class*='step']",

        # Input method selection
        "input_document": "[data-input-method='document'], [x-on\\:click*='document']",
        "input_youtube": "[data-input-method='youtube'], [x-on\\:click*='youtube']",
        "input_wizard": "[data-input-method='wizard']",
        "input_yaml": "[data-input-method='yaml']",

        # Document input
        "drag_drop_zone": ".drag-drop-zone, [x-data*='dragDrop']",
        "file_input": "input[type='file']",
        "document_path_input": "input[name='documentPath'], #documentPath",

        # YouTube input
        "youtube_url_input": "input[name='youtubeUrl'], #youtubeUrl",
        "youtube_validate_button": "[data-action='validate-youtube']",

        # Language selection
        "language_selector": "[x-data*='language'], .language-selector",
        "language_checkbox": "input[type='checkbox'][name='languages']",
        "language_option": "[data-language]",

        # Voice selection
        "voice_selector": "[x-data*='voice'], .voice-selector",
        "voice_radio": "input[type='radio'][name='voice']",
        "voice_option": "[data-voice]",

        # Video configuration
        "accent_color_selector": "[name='accentColor'], #accentColor",
        "video_count_input": "[name='videoCount'], #videoCount",
        "title_input": "[name='title'], #title",

        # Preview
        "preview_section": ".preview-section, [x-show*='preview']",
        "preview_content": ".preview-content",

        # Generation
        "generate_button": "[data-action='generate'], button[type='submit']",
        "progress_container": ".progress-container, [x-show*='progress']",
        "progress_bar": ".progress-bar, [role='progressbar']",
        "progress_text": ".progress-text, [x-text*='progress']",

        # Messages
        "error_message": ".error-message, [role='alert']",
        "success_message": ".success-message",
        "validation_feedback": ".validation-feedback",

        # Navigation
        "next_button": "[data-action='next'], .next-step",
        "back_button": "[data-action='back'], .prev-step",
        "cancel_button": "[data-action='cancel']",
    }

    def __init__(self, driver, base_url: str = "http://localhost:8000"):
        """
        Initialize the page object.

        Args:
            driver: Selenium WebDriver instance
            base_url: Base URL of the application
        """
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium is not installed. Install with: pip install selenium")

        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.short_wait = WebDriverWait(driver, 3)

    def navigate(self) -> "CreateUnifiedPage":
        """Navigate to the create page."""
        self.driver.get(f"{self.base_url}/create")
        self._wait_for_page_load()
        return self

    def _wait_for_page_load(self, timeout: int = 10):
        """Wait for page to fully load with Alpine.js initialized."""
        self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, self.SELECTORS["page_container"]))
        )
        # Wait for Alpine.js initialization
        time.sleep(0.5)

    def _find_element(self, selector_key: str, timeout: int = 10):
        """Find element by selector key."""
        selector = self.SELECTORS.get(selector_key, selector_key)
        try:
            return WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, selector))
            )
        except TimeoutException:
            return None

    def _find_elements(self, selector_key: str) -> List:
        """Find all elements matching selector."""
        selector = self.SELECTORS.get(selector_key, selector_key)
        return self.driver.find_elements(By.CSS_SELECTOR, selector)

    def _click_element(self, selector_key: str):
        """Click an element."""
        element = self._find_element(selector_key)
        if element:
            self.wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, self.SELECTORS.get(selector_key, selector_key))))
            element.click()
            time.sleep(0.3)  # Allow for Alpine.js state updates

    def _type_text(self, selector_key: str, text: str, clear_first: bool = True):
        """Type text into an input element."""
        element = self._find_element(selector_key)
        if element:
            if clear_first:
                element.clear()
            element.send_keys(text)

    # ==================== Input Method Selection ====================

    def select_document_input(self) -> "CreateUnifiedPage":
        """Select document input method."""
        self._click_element("input_document")
        return self

    def select_youtube_input(self) -> "CreateUnifiedPage":
        """Select YouTube input method."""
        self._click_element("input_youtube")
        return self

    def select_wizard_input(self) -> "CreateUnifiedPage":
        """Select wizard input method."""
        self._click_element("input_wizard")
        return self

    def select_yaml_input(self) -> "CreateUnifiedPage":
        """Select YAML input method."""
        self._click_element("input_yaml")
        return self

    # ==================== Document Upload ====================

    def upload_document(self, file_path: str) -> "CreateUnifiedPage":
        """
        Upload a document file.

        Args:
            file_path: Path to the document file
        """
        file_input = self._find_element("file_input")
        if file_input:
            file_input.send_keys(file_path)
            time.sleep(1)  # Wait for validation
        return self

    def enter_document_path(self, path: str) -> "CreateUnifiedPage":
        """
        Enter a document path manually.

        Args:
            path: Path to the document
        """
        self._type_text("document_path_input", path)
        return self

    def drag_and_drop_file(self, file_path: str) -> "CreateUnifiedPage":
        """
        Simulate drag and drop file upload.

        Note: This requires JavaScript execution for full simulation.
        """
        # For actual drag-drop, we need to use JavaScript
        # Simplified: just use file input
        return self.upload_document(file_path)

    # ==================== YouTube URL Entry ====================

    def enter_youtube_url(self, url: str) -> "CreateUnifiedPage":
        """
        Enter a YouTube URL.

        Args:
            url: YouTube video URL
        """
        self._type_text("youtube_url_input", url)
        return self

    def validate_youtube_url(self) -> "CreateUnifiedPage":
        """Click the validate button for YouTube URL."""
        self._click_element("youtube_validate_button")
        time.sleep(1)  # Wait for validation
        return self

    # ==================== Language Selection ====================

    def select_languages(self, lang_codes: List[str]) -> "CreateUnifiedPage":
        """
        Select multiple languages.

        Args:
            lang_codes: List of language codes (e.g., ['en', 'es', 'fr'])
        """
        for code in lang_codes:
            selector = f"[data-language='{code}'], input[value='{code}']"
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                if not element.is_selected():
                    element.click()
                    time.sleep(0.2)
            except NoSuchElementException:
                pass
        return self

    def get_selected_languages(self) -> List[str]:
        """Get list of currently selected language codes."""
        selected = []
        checkboxes = self._find_elements("language_checkbox")
        for checkbox in checkboxes:
            if checkbox.is_selected():
                selected.append(checkbox.get_attribute("value"))
        return selected

    # ==================== Voice Selection ====================

    def select_voices(self, lang_code: str, voice_ids: List[str]) -> "CreateUnifiedPage":
        """
        Select voices for a language.

        Args:
            lang_code: Language code
            voice_ids: List of voice IDs to select
        """
        for voice_id in voice_ids:
            selector = f"[data-voice='{voice_id}'], input[value='{voice_id}']"
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                element.click()
                time.sleep(0.2)
            except NoSuchElementException:
                pass
        return self

    def select_voice(self, voice_id: str) -> "CreateUnifiedPage":
        """
        Select a single voice.

        Args:
            voice_id: Voice identifier
        """
        radios = self._find_elements("voice_radio")
        for radio in radios:
            if radio.get_attribute("value") == voice_id:
                radio.click()
                break
        return self

    # ==================== Video Configuration ====================

    def set_accent_color(self, color: str) -> "CreateUnifiedPage":
        """
        Set the accent color.

        Args:
            color: Color name (blue, purple, orange, etc.)
        """
        selector = self._find_element("accent_color_selector")
        if selector:
            # Handle select dropdown
            from selenium.webdriver.support.ui import Select
            try:
                select = Select(selector)
                select.select_by_value(color)
            except:
                # Try clicking color option directly
                self._click_element(f"[data-color='{color}']")
        return self

    def set_video_count(self, count: int) -> "CreateUnifiedPage":
        """
        Set the number of videos to generate.

        Args:
            count: Number of videos
        """
        self._type_text("video_count_input", str(count))
        return self

    def set_title(self, title: str) -> "CreateUnifiedPage":
        """
        Set the video title.

        Args:
            title: Video title
        """
        self._type_text("title_input", title)
        return self

    # ==================== Generation ====================

    def start_generation(self) -> "CreateUnifiedPage":
        """Click the generate button to start video generation."""
        self._click_element("generate_button")
        return self

    def wait_for_progress(self, timeout: int = 120) -> bool:
        """
        Wait for progress indicator to appear.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if progress appeared, False otherwise
        """
        try:
            WebDriverWait(self.driver, timeout).until(
                EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, self.SELECTORS["progress_container"])
                )
            )
            return True
        except TimeoutException:
            return False

    def get_progress_percentage(self) -> int:
        """Get current progress percentage."""
        progress_bar = self._find_element("progress_bar")
        if progress_bar:
            # Try different attribute names
            value = (
                progress_bar.get_attribute("aria-valuenow") or
                progress_bar.get_attribute("data-progress") or
                progress_bar.get_attribute("style")
            )
            if value:
                try:
                    if "width:" in str(value):
                        return int(value.split("width:")[1].split("%")[0].strip())
                    return int(value)
                except:
                    pass
        return 0

    def wait_for_completion(self, timeout: int = 300) -> bool:
        """
        Wait for generation to complete.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if completed successfully, False otherwise
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            progress = self.get_progress_percentage()
            if progress >= 100:
                return True
            time.sleep(2)
        return False

    # ==================== Cancel Operation ====================

    def cancel_generation(self) -> "CreateUnifiedPage":
        """Cancel the current generation."""
        self._click_element("cancel_button")
        return self

    # ==================== Download ====================

    def download_video(self) -> bool:
        """
        Click download button if available.

        Returns:
            True if download started, False otherwise
        """
        try:
            download_btn = self.driver.find_element(
                By.CSS_SELECTOR, "[data-action='download'], .download-button"
            )
            download_btn.click()
            return True
        except NoSuchElementException:
            return False

    # ==================== State Verification ====================

    def get_current_step(self) -> int:
        """Get the current step number."""
        step_element = self._find_element("step_indicator")
        if step_element:
            text = step_element.text
            # Try to extract step number
            import re
            match = re.search(r'(\d+)', text)
            if match:
                return int(match.group(1))
        return 1

    def has_error(self) -> bool:
        """Check if there's an error message displayed."""
        error = self._find_element("error_message")
        return error is not None and error.is_displayed()

    def get_error_message(self) -> Optional[str]:
        """Get the current error message if any."""
        error = self._find_element("error_message")
        if error and error.is_displayed():
            return error.text
        return None

    def has_validation_error(self) -> bool:
        """Check if there's a validation error."""
        feedback = self._find_element("validation_feedback")
        if feedback:
            return "error" in feedback.get_attribute("class").lower()
        return False

    def is_preview_visible(self) -> bool:
        """Check if preview section is visible."""
        preview = self._find_element("preview_section")
        return preview is not None and preview.is_displayed()

    def is_generate_button_enabled(self) -> bool:
        """Check if generate button is enabled."""
        btn = self._find_element("generate_button")
        return btn is not None and btn.is_enabled()

    # ==================== Navigation ====================

    def click_next(self) -> "CreateUnifiedPage":
        """Click the next step button."""
        self._click_element("next_button")
        return self

    def click_back(self) -> "CreateUnifiedPage":
        """Click the back button."""
        self._click_element("back_button")
        return self

    # ==================== Accessibility Helpers ====================

    def tab_to_element(self, selector_key: str) -> "CreateUnifiedPage":
        """Tab to a specific element using keyboard navigation."""
        body = self.driver.find_element(By.TAG_NAME, "body")
        target = self._find_element(selector_key)

        if target:
            # Keep tabbing until we reach the target
            for _ in range(50):  # Max tabs
                active = self.driver.switch_to.active_element
                if active == target:
                    break
                body.send_keys(Keys.TAB)
                time.sleep(0.1)
        return self

    def press_enter(self) -> "CreateUnifiedPage":
        """Press Enter on the currently focused element."""
        self.driver.switch_to.active_element.send_keys(Keys.ENTER)
        return self

    def press_space(self) -> "CreateUnifiedPage":
        """Press Space on the currently focused element."""
        self.driver.switch_to.active_element.send_keys(Keys.SPACE)
        return self

    def get_focused_element_tag(self) -> str:
        """Get the tag name of the currently focused element."""
        return self.driver.switch_to.active_element.tag_name
