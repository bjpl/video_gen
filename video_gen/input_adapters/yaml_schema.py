"""YAML schema validation for video definitions.

This module handles comprehensive validation of YAML structures for both
video_set and single_video formats.
"""

from typing import Any, Dict, List


class YAMLValidationError(Exception):
    """Exception raised when YAML validation fails."""
    pass


class YAMLSchemaValidator:
    """Validates YAML schema for video configurations."""

    def validate_yaml_schema(
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
            errors.extend(self.validate_video_set_schema(yaml_data))
        elif format_type == "single_video":
            errors.extend(self.validate_single_video_schema(yaml_data))
        else:
            errors.append(
                "Unrecognized YAML format. Must contain 'videos' array (video_set) "
                "or 'video_id'/'scenes' (single_video)"
            )

        return errors

    def validate_video_set_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
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

            video_errors = self.validate_video_config_schema(video_data, f"videos[{i}]")
            errors.extend(video_errors)

        return errors

    def validate_single_video_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
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

        return self.validate_video_config_schema(video_data, "video")

    def validate_video_config_schema(
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

            scene_errors = self.validate_scene_config_schema(scene_data, f"{context}.scenes[{i}]")
            errors.extend(scene_errors)

        return errors

    def validate_scene_config_schema(
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

    def detect_format(self, yaml_data: Dict[str, Any]) -> str:
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


__all__ = ["YAMLValidationError", "YAMLSchemaValidator"]
