"""YAML file input adapter for structured video definitions.

This adapter processes YAML configuration files that define video structure,
scenes, and content in a declarative format.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
import re

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, VideoConfig, SceneConfig


class YAMLValidationError(Exception):
    """Exception raised when YAML validation fails."""
    pass


class YAMLFileAdapter(InputAdapter):
    """Adapter for YAML configuration files.

    This adapter reads YAML files containing structured video definitions
    and converts them into VideoSet objects for video generation.

    Security Features:
    - Path traversal prevention (files must be under project root)
    - System directory blocking (/etc, /root, etc.)
    - 10MB file size limit
    - Safe YAML parsing (yaml.safe_load)
    - Test mode support for testing with temporary files
    """

    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10_000_000

    # System directories to block (security)
    SYSTEM_DIRS = ['/etc', '/sys', '/proc', '/root', '/boot', '/var', '/usr', '/bin', '/sbin']

    def __init__(self, test_mode: bool = False):
        """Initialize the YAML file adapter.

        Args:
            test_mode: If True, bypass security checks for testing purposes.
                      This allows reading files outside the project directory.
        """
        super().__init__(
            name="yaml",
            description="Processes YAML configuration files"
        )
        self.test_mode = test_mode
        self.supported_formats = {".yaml", ".yml"}
        self._template_cache = {}  # Cache loaded templates for performance

    def _get_template_dir(self) -> Path:
        """Get the templates directory path.

        Returns:
            Path to templates directory
        """
        return Path(__file__).parent / "templates"

    def _load_template(self, template_name: str) -> Dict[str, Any]:
        """Load a template from the templates directory.

        Templates are YAML files that define reusable video structures
        with variable placeholders (${variable_name} or ${variable|default}).

        Args:
            template_name: Name of template (without .yaml extension)

        Returns:
            Parsed template data as dictionary

        Raises:
            ValueError: If template doesn't exist or is invalid
        """
        # Check cache first
        if template_name in self._template_cache:
            return self._template_cache[template_name].copy()

        template_dir = self._get_template_dir()
        template_path = template_dir / f"{template_name}.yaml"

        if not template_path.exists():
            available = [f.stem for f in template_dir.glob("*.yaml")]
            raise ValueError(
                f"Template '{template_name}' not found. "
                f"Available templates: {', '.join(available)}"
            )

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)

            if not isinstance(template_data, dict):
                raise ValueError(
                    f"Invalid template '{template_name}': root must be a dictionary"
                )

            # Cache the template
            self._template_cache[template_name] = template_data.copy()

            return template_data

        except yaml.YAMLError as e:
            raise ValueError(f"Template '{template_name}' has invalid YAML: {str(e)}")

    def _substitute_variables(
        self,
        text: str,
        variables: Dict[str, Any]
    ) -> str:
        """Substitute variables in text using ${var} or ${var|default} syntax.

        Supports:
        - ${variable_name} - Simple substitution
        - ${variable_name|default_value} - With default fallback

        Args:
            text: Text containing variable placeholders
            variables: Dictionary of variable values

        Returns:
            Text with variables substituted
        """
        if not isinstance(text, str):
            return text

        # Pattern matches ${variable} or ${variable|default}
        pattern = r'\$\{([^}|]+)(?:\|([^}]*))?\}'

        def replace_var(match):
            var_name = match.group(1).strip()
            default_value = match.group(2) if match.group(2) is not None else ""

            # Get value from variables or use default
            value = variables.get(var_name, default_value)

            # Convert to string
            return str(value) if value is not None else default_value

        return re.sub(pattern, replace_var, text)

    def _merge_template(
        self,
        template_data: Dict[str, Any],
        override_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge template with user-provided overrides and substitute variables.

        Process:
        1. Extract variables from override_data
        2. Deep merge override_data into template_data
        3. Recursively substitute all ${variable} placeholders

        Args:
            template_data: Base template data
            override_data: User override data (including 'variables' key)

        Returns:
            Merged data with variables substituted
        """
        # Extract variables (remove from result)
        variables = override_data.pop("variables", {})

        # Deep merge override_data into template_data
        merged = self._deep_merge(template_data.copy(), override_data)

        # Recursively substitute variables
        return self._substitute_all_variables(merged, variables)

    def _deep_merge(
        self,
        base: Dict[str, Any],
        override: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deep merge two dictionaries, with override taking precedence.

        Args:
            base: Base dictionary
            override: Override dictionary

        Returns:
            Merged dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge dictionaries
                result[key] = self._deep_merge(result[key], value)
            elif key in result and isinstance(result[key], list) and isinstance(value, list):
                # Extend lists (could also replace - depends on use case)
                result[key] = result[key] + value
            else:
                # Override value
                result[key] = value

        return result

    def _substitute_all_variables(
        self,
        data: Any,
        variables: Dict[str, Any]
    ) -> Any:
        """Recursively substitute variables in all strings in data structure.

        Args:
            data: Data structure (dict, list, str, etc.)
            variables: Variable substitution dictionary

        Returns:
            Data with all variables substituted
        """
        if isinstance(data, dict):
            return {
                k: self._substitute_all_variables(v, variables)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [
                self._substitute_all_variables(item, variables)
                for item in data
            ]
        elif isinstance(data, str):
            return self._substitute_variables(data, variables)
        else:
            return data

    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates with their descriptions.

        Returns:
            List of template info dictionaries with 'name' and 'description' keys
        """
        template_dir = self._get_template_dir()
        templates = []

        for template_path in sorted(template_dir.glob("*.yaml")):
            template_name = template_path.stem
            try:
                template_data = self._load_template(template_name)

                # Extract description from template comments or description field
                description = template_data.get("description", "")

                if not description:
                    # Try to read first comment line from file
                    with open(template_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines[:5]:  # Check first 5 lines
                            if line.strip().startswith("# ") and not line.startswith("# Variables"):
                                description = line[2:].strip()
                                break

                templates.append({
                    "name": template_name,
                    "description": description or f"Template: {template_name}"
                })
            except Exception:
                # Skip invalid templates
                continue

        return templates

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        """Adapt a YAML file to VideoSet structure.

        Args:
            source: Path to YAML file
            **kwargs: Additional parameters (accent_color, voice, etc.)

        Returns:
            InputAdapterResult with VideoSet
        """
        try:
            # Read and validate YAML file with security checks
            yaml_data = await self._read_yaml_file(source)

            if yaml_data is None:
                return InputAdapterResult(
                    success=False,
                    error=f"Failed to read YAML file: {source}"
                )

            # Process template if specified
            if "template" in yaml_data:
                template_name = yaml_data.pop("template")
                try:
                    template_data = self._load_template(template_name)
                    yaml_data = self._merge_template(template_data, yaml_data)
                except ValueError as e:
                    return InputAdapterResult(
                        success=False,
                        error=f"Template error: {str(e)}"
                    )

            # Detect format: single video vs video set
            format_type = self._detect_format(yaml_data)

            # Validate YAML schema before processing
            validation_errors = self._validate_yaml_schema(yaml_data, format_type)
            if validation_errors:
                error_message = "YAML validation failed:\n" + "\n".join(
                    f"  - {error}" for error in validation_errors
                )
                return InputAdapterResult(
                    success=False,
                    error=error_message
                )

            # Convert YAML data to VideoSet based on format
            if format_type == "video_set":
                video_set = self._parse_video_set(yaml_data, source, **kwargs)
            elif format_type == "single_video":
                video_set = self._parse_single_video(yaml_data, source, **kwargs)
            else:
                return InputAdapterResult(
                    success=False,
                    error=f"Unrecognized YAML format. Must contain 'videos' (set) or 'video_id' (single)"
                )

            return InputAdapterResult(
                success=True,
                video_set=video_set,
                metadata={
                    "source": str(source),
                    "format_type": format_type,
                    "videos_generated": len(video_set.videos)
                }
            )

        except yaml.YAMLError as e:
            return InputAdapterResult(
                success=False,
                error=f"YAML parsing error: {str(e)}"
            )
        except YAMLValidationError as e:
            return InputAdapterResult(
                success=False,
                error=f"YAML validation error: {str(e)}"
            )
        except Exception as e:
            return InputAdapterResult(
                success=False,
                error=f"YAML adaptation failed: {str(e)}"
            )

    async def _read_yaml_file(self, source: Any) -> Dict[str, Any]:
        """Read YAML file with comprehensive security validation.

        Security checks:
        - Path traversal prevention
        - System directory blocking
        - File size limit (10MB)
        - Safe YAML parsing

        Args:
            source: Path to YAML file

        Returns:
            Parsed YAML data as dictionary

        Raises:
            ValueError: If security validation fails
            FileNotFoundError: If file doesn't exist
        """
        # Clean the source path - strip quotes and whitespace
        source_str = str(source).strip().strip('"').strip("'")
        file_path = Path(source_str)

        # Security: Resolve to absolute path to detect traversal attempts
        try:
            file_path = file_path.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid file path: {e}")

        # Get project root (3 levels up from this file)
        project_root = Path(__file__).parent.parent.parent.resolve()

        # CRITICAL SECURITY: Block absolute paths to system directories
        # This prevents access to sensitive files like /etc/passwd, /root/.ssh/id_rsa, etc.
        file_path_str = str(file_path)
        if any(file_path_str.startswith(d) for d in self.SYSTEM_DIRS):
            raise ValueError(f"Access to system directories denied: {file_path}")

        # Path traversal protection with whitelist approach
        # Allow: project files, /tmp directory, project uploads/ directory
        # Block: parent directory traversal, unauthorized paths
        if not self.test_mode:
            # Define allowed base paths
            allowed_paths = [
                project_root,  # Project directory
                Path("/tmp"),  # System temp directory (for uploads)
                project_root / "uploads"  # Project uploads directory
            ]

            # Check if file is under any allowed path
            is_allowed = False
            for allowed_path in allowed_paths:
                try:
                    file_path.relative_to(allowed_path)
                    is_allowed = True
                    break
                except ValueError:
                    continue

            if not is_allowed:
                # Build helpful error message
                allowed_paths_str = ", ".join(str(p) for p in allowed_paths)
                raise ValueError(
                    f"Path traversal detected: {file_path} is not under any allowed directory. "
                    f"Allowed directories: {allowed_paths_str}"
                )

            # Additional security: Detect parent directory traversal in original source
            if ".." in source_str:
                raise ValueError(f"Path traversal pattern detected in source: {source_str}")

        # Validate file exists and is actually a file
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        # File size limit (10MB)
        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"File too large: {file_size} bytes (max {self.MAX_FILE_SIZE})"
            )

        # Validate file extension
        if file_path.suffix.lower() not in self.supported_formats:
            raise ValueError(
                f"Invalid file extension: {file_path.suffix} (must be .yaml or .yml)"
            )

        # Read and parse YAML file safely
        try:
            content = file_path.read_text(encoding='utf-8')
            # Use yaml.safe_load for security (prevents arbitrary code execution)
            yaml_data = yaml.safe_load(content)

            if not isinstance(yaml_data, dict):
                raise ValueError(
                    f"Invalid YAML structure: root must be a dictionary, got {type(yaml_data)}"
                )

            return yaml_data

        except yaml.YAMLError as e:
            raise ValueError(f"YAML parsing error: {str(e)}")
        except UnicodeDecodeError as e:
            raise ValueError(f"File encoding error: {str(e)} (must be UTF-8)")

    def _validate_yaml_schema(
        self,
        yaml_data: Dict[str, Any],
        format_type: str
    ) -> List[str]:
        """Validate YAML structure and return list of errors.

        Args:
            yaml_data: Parsed YAML data
            format_type: Detected format type ("video_set" or "single_video")

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if format_type == "video_set":
            errors.extend(self._validate_video_set_schema(yaml_data))
        elif format_type == "single_video":
            errors.extend(self._validate_single_video_schema(yaml_data))
        else:
            errors.append(
                "Unrecognized YAML format. Must contain 'videos' array (video_set) "
                "or 'video_id'/'scenes' (single_video)"
            )

        return errors

    def _validate_video_set_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
        """Validate video_set format schema.

        Expected structure:
        ```yaml
        set_id: my_set          # optional
        name: My Video Set      # optional
        videos:                 # required
          - video_id: video_1   # required
            title: Video 1      # required
            scenes: [...]       # required
        ```

        Args:
            yaml_data: Parsed YAML data

        Returns:
            List of validation errors
        """
        errors = []

        # Validate 'videos' field
        if "videos" not in yaml_data:
            errors.append("Missing required field: 'videos'")
            return errors  # Can't continue without videos array

        videos = yaml_data["videos"]
        if not isinstance(videos, list):
            errors.append(f"Field 'videos' must be a list, got {type(videos).__name__}")
            return errors

        if len(videos) == 0:
            errors.append("Field 'videos' cannot be empty (must contain at least one video)")
            return errors

        if len(videos) > 100:
            errors.append(f"Too many videos: {len(videos)} (maximum 100)")

        # Validate each video in the set
        for i, video_data in enumerate(videos):
            if not isinstance(video_data, dict):
                errors.append(
                    f"videos[{i}]: Video must be a dictionary, got {type(video_data).__name__}"
                )
                continue

            video_errors = self._validate_video_config_schema(video_data, f"videos[{i}]")
            errors.extend(video_errors)

        return errors

    def _validate_single_video_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
        """Validate single_video format schema.

        Expected structure:
        ```yaml
        video_id: my_video      # required (or 'id')
        title: My Video         # required
        scenes:                 # required
          - scene_id: scene_1
            scene_type: title
            narration: "..."
        ```

        Args:
            yaml_data: Parsed YAML data

        Returns:
            List of validation errors
        """
        # Check for nested 'video' key (alternative format)
        if "video" in yaml_data and isinstance(yaml_data["video"], dict):
            video_data = {**yaml_data["video"], **yaml_data}
        else:
            video_data = yaml_data

        return self._validate_video_config_schema(video_data, "video")

    def _validate_video_config_schema(
        self,
        video_data: Dict[str, Any],
        context: str = "video"
    ) -> List[str]:
        """Validate a single video configuration.

        Args:
            video_data: Video data dictionary
            context: Context for error messages (e.g., "videos[0]")

        Returns:
            List of validation errors
        """
        errors = []

        # Validate video_id or id (one is required)
        if "video_id" not in video_data and "id" not in video_data:
            errors.append(f"{context}: Missing required field 'video_id' or 'id'")
        else:
            video_id = video_data.get("video_id") or video_data.get("id")
            if not isinstance(video_id, str):
                errors.append(
                    f"{context}.video_id: Must be a string, got {type(video_id).__name__}"
                )
            elif len(video_id) > 200:
                errors.append(
                    f"{context}.video_id: Too long ({len(video_id)} chars, max 200)"
                )

        # Validate title (required)
        if "title" not in video_data:
            errors.append(f"{context}: Missing required field 'title'")
        else:
            title = video_data["title"]
            if not isinstance(title, str):
                errors.append(
                    f"{context}.title: Must be a string, got {type(title).__name__}"
                )
            elif len(title) > 500:
                errors.append(
                    f"{context}.title: Too long ({len(title)} chars, max 500)"
                )

        # Validate description (optional but typed)
        if "description" in video_data:
            description = video_data["description"]
            if not isinstance(description, str):
                errors.append(
                    f"{context}.description: Must be a string, got {type(description).__name__}"
                )
            elif len(description) > 5000:
                errors.append(
                    f"{context}.description: Too long ({len(description)} chars, max 5000)"
                )

        # Validate accent_color (optional but validated)
        if "accent_color" in video_data:
            accent_color = video_data["accent_color"]
            if not isinstance(accent_color, str):
                errors.append(
                    f"{context}.accent_color: Must be a string, got {type(accent_color).__name__}"
                )

        # Validate voices/voice (optional but typed)
        if "voices" in video_data:
            voices = video_data["voices"]
            if not isinstance(voices, list):
                errors.append(
                    f"{context}.voices: Must be a list, got {type(voices).__name__}"
                )
            elif not all(isinstance(v, str) for v in voices):
                errors.append(f"{context}.voices: All items must be strings")
        elif "voice" in video_data:
            voice = video_data["voice"]
            if not isinstance(voice, str):
                errors.append(
                    f"{context}.voice: Must be a string, got {type(voice).__name__}"
                )

        # Validate scenes (required)
        if "scenes" not in video_data:
            errors.append(f"{context}: Missing required field 'scenes'")
            return errors  # Can't continue without scenes

        scenes = video_data["scenes"]
        if not isinstance(scenes, list):
            errors.append(
                f"{context}.scenes: Must be a list, got {type(scenes).__name__}"
            )
            return errors

        if len(scenes) == 0:
            errors.append(f"{context}.scenes: Cannot be empty (must contain at least one scene)")
            return errors

        if len(scenes) > 100:
            errors.append(f"{context}.scenes: Too many scenes ({len(scenes)}, max 100)")

        # Validate each scene
        for i, scene_data in enumerate(scenes):
            if not isinstance(scene_data, dict):
                errors.append(
                    f"{context}.scenes[{i}]: Scene must be a dictionary, got {type(scene_data).__name__}"
                )
                continue

            scene_errors = self._validate_scene_config_schema(scene_data, f"{context}.scenes[{i}]")
            errors.extend(scene_errors)

        return errors

    def _validate_scene_config_schema(
        self,
        scene_data: Dict[str, Any],
        context: str = "scene"
    ) -> List[str]:
        """Validate a single scene configuration.

        Args:
            scene_data: Scene data dictionary
            context: Context for error messages (e.g., "scenes[0]")

        Returns:
            List of validation errors
        """
        errors = []

        # Validate scene_id (required)
        if "scene_id" not in scene_data:
            errors.append(f"{context}: Missing required field 'scene_id'")
        else:
            scene_id = scene_data["scene_id"]
            if not isinstance(scene_id, str):
                errors.append(
                    f"{context}.scene_id: Must be a string, got {type(scene_id).__name__}"
                )
            elif len(scene_id) > 200:
                errors.append(
                    f"{context}.scene_id: Too long ({len(scene_id)} chars, max 200)"
                )

        # Validate scene_type (required - support both 'scene_type' and 'type')
        has_type = "scene_type" in scene_data or "type" in scene_data
        if not has_type:
            errors.append(f"{context}: Missing required field 'scene_type' or 'type'")
        else:
            scene_type = scene_data.get("scene_type") or scene_data.get("type")
            if not isinstance(scene_type, str):
                errors.append(
                    f"{context}.scene_type: Must be a string, got {type(scene_type).__name__}"
                )
            else:
                # Validate against allowed scene types
                valid_types = [
                    "title", "command", "list", "outro", "code_comparison", "quote",
                    "learning_objectives", "problem", "solution", "checkpoint", "quiz", "exercise"
                ]
                if scene_type not in valid_types:
                    errors.append(
                        f"{context}.scene_type: Invalid type '{scene_type}'. "
                        f"Must be one of: {', '.join(valid_types)}"
                    )

        # Validate narration (required)
        if "narration" not in scene_data:
            errors.append(f"{context}: Missing required field 'narration'")
        else:
            narration = scene_data["narration"]
            if not isinstance(narration, str):
                errors.append(
                    f"{context}.narration: Must be a string, got {type(narration).__name__}"
                )
            elif len(narration) > 50000:
                errors.append(
                    f"{context}.narration: Too long ({len(narration)} chars, max 50000)"
                )

        # Validate visual_content (optional but must be dict if present)
        if "visual_content" in scene_data:
            visual_content = scene_data["visual_content"]
            if not isinstance(visual_content, dict):
                errors.append(
                    f"{context}.visual_content: Must be a dictionary, got {type(visual_content).__name__}"
                )

        # Validate voice (optional but typed)
        if "voice" in scene_data:
            voice = scene_data["voice"]
            if not isinstance(voice, str):
                errors.append(
                    f"{context}.voice: Must be a string, got {type(voice).__name__}"
                )

        # Validate durations (optional but typed and constrained)
        if "min_duration" in scene_data:
            min_duration = scene_data["min_duration"]
            if not isinstance(min_duration, (int, float)):
                errors.append(
                    f"{context}.min_duration: Must be a number, got {type(min_duration).__name__}"
                )
            elif min_duration < 0 or min_duration > 300:
                errors.append(
                    f"{context}.min_duration: Out of range ({min_duration}, must be 0-300)"
                )

        if "max_duration" in scene_data:
            max_duration = scene_data["max_duration"]
            if not isinstance(max_duration, (int, float)):
                errors.append(
                    f"{context}.max_duration: Must be a number, got {type(max_duration).__name__}"
                )
            elif max_duration < 0 or max_duration > 300:
                errors.append(
                    f"{context}.max_duration: Out of range ({max_duration}, must be 0-300)"
                )

        # Cross-field validation: min_duration <= max_duration
        if "min_duration" in scene_data and "max_duration" in scene_data:
            min_dur = scene_data["min_duration"]
            max_dur = scene_data["max_duration"]
            if isinstance(min_dur, (int, float)) and isinstance(max_dur, (int, float)):
                if min_dur > max_dur:
                    errors.append(
                        f"{context}: min_duration ({min_dur}) cannot be greater than "
                        f"max_duration ({max_dur})"
                    )

        return errors

    def _detect_format(self, yaml_data: Dict[str, Any]) -> str:
        """Detect YAML format type.

        Formats:
        - "video_set": Contains 'videos' key (even if not a valid list)
        - "single_video": Contains 'video_id' or 'scenes' for a single video, or nested 'video' key
        - "unknown": Neither format detected

        Args:
            yaml_data: Parsed YAML data

        Returns:
            Format type string ("video_set", "single_video", or "unknown")
        """
        # Check for video_set format (even if videos is invalid, validation will catch it)
        if "videos" in yaml_data:
            return "video_set"
        # Check for single_video format (including nested 'video' key)
        elif "video_id" in yaml_data or "id" in yaml_data or "scenes" in yaml_data or "video" in yaml_data:
            return "single_video"
        else:
            return "unknown"

    def _parse_video_set(
        self,
        yaml_data: Dict[str, Any],
        source: Any,
        **kwargs
    ) -> VideoSet:
        """Parse video set format (multiple videos).

        Expected structure:
        ```yaml
        set_id: my_video_set
        name: My Video Set
        description: A collection of videos
        videos:
          - video_id: video_1
            title: Video 1
            scenes: [...]
          - video_id: video_2
            title: Video 2
            scenes: [...]
        ```

        Args:
            yaml_data: Parsed YAML data
            source: Original source path
            **kwargs: Additional parameters

        Returns:
            VideoSet object
        """
        # Extract set-level metadata
        set_id = yaml_data.get("set_id", Path(source).stem)
        name = yaml_data.get("name", "Video Set")
        description = yaml_data.get("description", f"Generated from {source}")
        metadata = yaml_data.get("metadata", {})

        # Parse videos
        videos = []
        for video_data in yaml_data.get("videos", []):
            video = self._parse_video_config(video_data, **kwargs)
            videos.append(video)

        return VideoSet(
            set_id=set_id,
            name=name,
            description=description,
            videos=videos,
            metadata=metadata
        )

    def _parse_single_video(
        self,
        yaml_data: Dict[str, Any],
        source: Any,
        **kwargs
    ) -> VideoSet:
        """Parse single video format (wrapped in VideoSet).

        Expected structure:
        ```yaml
        video_id: my_video
        title: My Video
        description: A single video
        scenes:
          - scene_id: scene_1
            scene_type: title
            narration: "Welcome"
            visual_content: {...}
        ```

        Args:
            yaml_data: Parsed YAML data
            source: Original source path
            **kwargs: Additional parameters

        Returns:
            VideoSet with single video
        """
        # Extract video metadata from nested 'video' key if present
        video_metadata = yaml_data.get("video", {})

        # Merge video metadata with yaml_data for backward compatibility
        # video_data should include both video metadata AND scenes
        video_data = {**video_metadata, **yaml_data}

        # Parse the single video with merged data
        video = self._parse_video_config(video_data, **kwargs)

        # Use video metadata for set-level data, fall back to merged data
        set_id = video_metadata.get("id") or yaml_data.get("video_id", Path(source).stem)
        return VideoSet(
            set_id=f"{set_id}_set",
            name=video_metadata.get("title") or yaml_data.get("title", "Single Video"),
            description=video_metadata.get("description") or yaml_data.get("description", f"Generated from {source}"),
            videos=[video],
            metadata={"source": str(source)}
        )

    def _parse_video_config(
        self,
        video_data: Dict[str, Any],
        **kwargs
    ) -> VideoConfig:
        """Parse a single video configuration.

        Args:
            video_data: Video data from YAML
            **kwargs: Override parameters (accent_color, voice, etc.)

        Returns:
            VideoConfig object
        """
        # Extract video metadata with kwargs overrides
        # Support both 'video_id' and 'id' keys for backward compatibility
        video_id = video_data.get("video_id") or video_data.get("id", "video_1")
        title = video_data.get("title", "Untitled Video")
        description = video_data.get("description", "")
        accent_color = kwargs.get("accent_color") or video_data.get("accent_color", "blue")

        # Handle both 'voice' (single) and 'voices' (list) for backward compatibility
        voice = video_data.get("voice")
        if voice:
            voices = [voice] if isinstance(voice, str) else voice
        else:
            voices = video_data.get("voices", ["male"])

        # Parse scenes
        scenes = []
        for scene_data in video_data.get("scenes", []):
            scene = self._parse_scene_config(scene_data, **kwargs)
            scenes.append(scene)

        return VideoConfig(
            video_id=video_id,
            title=title,
            description=description,
            scenes=scenes,
            accent_color=accent_color,
            voices=voices
        )

    def _parse_scene_config(
        self,
        scene_data: Dict[str, Any],
        **kwargs
    ) -> SceneConfig:
        """Parse a single scene configuration.

        Args:
            scene_data: Scene data from YAML
            **kwargs: Override parameters (voice, etc.)

        Returns:
            SceneConfig object
        """
        # Extract scene data with validation
        scene_id = scene_data.get("scene_id", "scene_1")

        # Support both 'scene_type' and 'type' for backward compatibility
        scene_type = scene_data.get("scene_type") or scene_data.get("type", "title")

        narration = scene_data.get("narration", "")

        # If visual_content not provided, use scene_data itself (old format)
        # Old format: scene has 'title', 'header', 'commands', etc. at top level
        # New format: scene has 'visual_content' dict with those fields
        visual_content = scene_data.get("visual_content", scene_data)

        voice = kwargs.get("voice") or scene_data.get("voice", "male")
        min_duration = scene_data.get("min_duration", 3.0)
        max_duration = scene_data.get("max_duration", 15.0)

        return SceneConfig(
            scene_id=scene_id,
            scene_type=scene_type,
            narration=narration,
            visual_content=visual_content,
            voice=voice,
            min_duration=min_duration,
            max_duration=max_duration
        )

    async def validate_source(self, source: Any) -> bool:
        """Validate YAML file.

        Args:
            source: Path to YAML file

        Returns:
            True if valid, False otherwise
        """
        if not isinstance(source, (str, Path)):
            return False

        file_path = Path(source)
        return (
            file_path.exists()
            and file_path.is_file()
            and file_path.suffix.lower() in {".yaml", ".yml"}
        )

    def supports_format(self, format_type: str) -> bool:
        """Check if format is supported.

        Args:
            format_type: File extension

        Returns:
            True if ".yaml" or ".yml"
        """
        return format_type.lower() in {".yaml", ".yml"}

    def export_to_yaml(
        self,
        video_set: VideoSet,
        output_path: Path,
        format_type: str = "video_set"
    ) -> bool:
        """Export VideoSet to YAML file.

        Args:
            video_set: VideoSet object to export
            output_path: Path to write YAML file
            format_type: Output format ("video_set" or "single_video")

        Returns:
            True if successful, False otherwise

        Raises:
            ValueError: If format_type is invalid or video_set is empty
        """
        if format_type not in ["video_set", "single_video"]:
            raise ValueError(f"Invalid format_type: {format_type}. Must be 'video_set' or 'single_video'")

        if not video_set.videos:
            raise ValueError("Cannot export empty VideoSet")

        if format_type == "single_video" and len(video_set.videos) > 1:
            raise ValueError(
                f"Cannot export {len(video_set.videos)} videos as 'single_video' format. "
                "Use 'video_set' format or export only the first video."
            )

        try:
            # Convert VideoSet to dictionary
            if format_type == "video_set":
                yaml_dict = self._video_set_to_yaml(video_set)
            else:  # single_video
                yaml_dict = self._video_config_to_yaml(video_set.videos[0])

            # Write to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(
                    yaml_dict,
                    f,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                    width=120
                )

            return True

        except Exception as e:
            raise RuntimeError(f"Failed to export YAML: {str(e)}")

    def _video_set_to_yaml(self, video_set: VideoSet) -> Dict[str, Any]:
        """Convert VideoSet to YAML-compatible dictionary (video_set format).

        Args:
            video_set: VideoSet object

        Returns:
            Dictionary ready for YAML serialization
        """
        yaml_dict = {
            "set_id": video_set.set_id,
            "name": video_set.name,
            "description": video_set.description,
            "videos": []
        }

        # Add metadata if present (excluding generated fields)
        if video_set.metadata:
            # Filter out runtime metadata
            filtered_metadata = {
                k: v for k, v in video_set.metadata.items()
                if k not in ["source", "videos_generated", "generation_timestamp"]
            }
            if filtered_metadata:
                yaml_dict["metadata"] = filtered_metadata

        # Convert each video
        for video in video_set.videos:
            video_dict = self._video_config_to_yaml(video, include_wrapper=False)
            yaml_dict["videos"].append(video_dict)

        return yaml_dict

    def _video_config_to_yaml(
        self,
        video: VideoConfig,
        include_wrapper: bool = True
    ) -> Dict[str, Any]:
        """Convert VideoConfig to YAML-compatible dictionary.

        Args:
            video: VideoConfig object
            include_wrapper: If True, wrap in single_video format structure

        Returns:
            Dictionary ready for YAML serialization
        """
        video_dict = {
            "video_id": video.video_id,
            "title": video.title,
            "description": video.description,
            "accent_color": video.accent_color,
            "scenes": []
        }

        # Add voices (handle both single voice and multiple voices)
        if video.voices:
            if len(video.voices) == 1:
                video_dict["voice"] = video.voices[0]
            else:
                video_dict["voices"] = video.voices

        # Convert each scene
        for scene in video.scenes:
            scene_dict = self._scene_config_to_yaml(scene)
            video_dict["scenes"].append(scene_dict)

        return video_dict

    def _scene_config_to_yaml(self, scene: SceneConfig) -> Dict[str, Any]:
        """Convert SceneConfig to YAML-compatible dictionary.

        Args:
            scene: SceneConfig object

        Returns:
            Dictionary ready for YAML serialization
        """
        scene_dict = {
            "scene_id": scene.scene_id,
            "scene_type": scene.scene_type,
            "narration": scene.narration,
            "visual_content": scene.visual_content,
        }

        # Add optional fields if they differ from defaults
        if scene.voice != "male":
            scene_dict["voice"] = scene.voice

        if scene.min_duration != 3.0:
            scene_dict["min_duration"] = scene.min_duration

        if scene.max_duration != 15.0:
            scene_dict["max_duration"] = scene.max_duration

        return scene_dict
