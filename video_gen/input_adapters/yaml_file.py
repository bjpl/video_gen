"""YAML file input adapter for structured video definitions.

This adapter processes YAML configuration files that define video structure,
scenes, and content in a declarative format.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from .base import InputAdapter, InputAdapterResult
from ..shared.models import VideoSet, VideoConfig, SceneConfig
from .yaml_schema import YAMLValidationError, YAMLSchemaValidator
from .yaml_templates import YAMLTemplateManager
from .yaml_resolvers import YAMLPathResolver, YAMLVariableSubstitution


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

    # Class constants for backward compatibility
    MAX_FILE_SIZE = 10_000_000
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

        # Get project root (3 levels up from this file)
        project_root = Path(__file__).parent.parent.parent.resolve()

        # Initialize components
        self.schema_validator = YAMLSchemaValidator()
        self.template_manager = YAMLTemplateManager(self._get_template_dir())
        self.path_resolver = YAMLPathResolver(project_root, test_mode)

        # Backward compatibility: expose internal template cache
        self._template_cache = self.template_manager._template_cache

    def _get_template_dir(self) -> Path:
        """Get the templates directory path.

        Returns:
            Path to templates directory
        """
        return Path(__file__).parent / "templates"

    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates with their descriptions.

        Returns:
            List of template info dictionaries with 'name' and 'description' keys
        """
        return self.template_manager.list_templates()

    # Backward compatibility methods - delegate to internal components
    async def _read_yaml_file(self, source: Any) -> Dict[str, Any]:
        """Read YAML file (backward compatibility).

        Delegates to YAMLPathResolver.

        Args:
            source: Path to YAML file

        Returns:
            Parsed YAML data
        """
        return await self.path_resolver.read_yaml_file(source)

    def _load_template(self, template_name: str) -> Dict[str, Any]:
        """Load template (backward compatibility).

        Delegates to YAMLTemplateManager.

        Args:
            template_name: Template name

        Returns:
            Template data
        """
        return self.template_manager.load_template(template_name)

    def _substitute_variables(self, text: str, variables: Dict[str, Any]) -> str:
        """Substitute variables (backward compatibility).

        Delegates to YAMLVariableSubstitution.

        Args:
            text: Text with placeholders
            variables: Variable values

        Returns:
            Substituted text
        """
        return YAMLVariableSubstitution.substitute_variables(text, variables)

    def _substitute_all_variables(self, data: Any, variables: Dict[str, Any]) -> Any:
        """Recursively substitute variables (backward compatibility).

        Delegates to YAMLVariableSubstitution.

        Args:
            data: Data structure
            variables: Variable values

        Returns:
            Data with substituted variables
        """
        return YAMLVariableSubstitution.substitute_all_variables(data, variables)

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge dictionaries (backward compatibility).

        Delegates to YAMLVariableSubstitution.

        Args:
            base: Base dictionary
            override: Override dictionary

        Returns:
            Merged dictionary
        """
        return YAMLVariableSubstitution.deep_merge(base, override)

    def _merge_template(
        self,
        template_data: Dict[str, Any],
        override_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge template with overrides (backward compatibility).

        Delegates to YAMLVariableSubstitution.

        Args:
            template_data: Template data
            override_data: Override data

        Returns:
            Merged data
        """
        return YAMLVariableSubstitution.merge_template(template_data, override_data)

    def _detect_format(self, yaml_data: Dict[str, Any]) -> str:
        """Detect YAML format (backward compatibility).

        Delegates to YAMLSchemaValidator.

        Args:
            yaml_data: YAML data

        Returns:
            Format type
        """
        return self.schema_validator.detect_format(yaml_data)

    def _validate_yaml_schema(
        self,
        yaml_data: Dict[str, Any],
        format_type: str
    ) -> List[str]:
        """Validate YAML schema (backward compatibility).

        Delegates to YAMLSchemaValidator.

        Args:
            yaml_data: YAML data
            format_type: Format type

        Returns:
            List of validation errors
        """
        return self.schema_validator.validate_yaml_schema(yaml_data, format_type)

    def _validate_video_set_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
        """Validate video set schema (backward compatibility).

        Args:
            yaml_data: YAML data

        Returns:
            List of errors
        """
        return self.schema_validator.validate_video_set_schema(yaml_data)

    def _validate_single_video_schema(self, yaml_data: Dict[str, Any]) -> List[str]:
        """Validate single video schema (backward compatibility).

        Args:
            yaml_data: YAML data

        Returns:
            List of errors
        """
        return self.schema_validator.validate_single_video_schema(yaml_data)

    def _validate_video_config_schema(
        self,
        video_data: Dict[str, Any],
        context: str = "video"
    ) -> List[str]:
        """Validate video config schema (backward compatibility).

        Args:
            video_data: Video data
            context: Error context

        Returns:
            List of errors
        """
        return self.schema_validator.validate_video_config_schema(video_data, context)

    def _validate_scene_config_schema(
        self,
        scene_data: Dict[str, Any],
        context: str = "scene"
    ) -> List[str]:
        """Validate scene config schema (backward compatibility).

        Args:
            scene_data: Scene data
            context: Error context

        Returns:
            List of errors
        """
        return self.schema_validator.validate_scene_config_schema(scene_data, context)

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
            yaml_data = await self.path_resolver.read_yaml_file(source)

            if yaml_data is None:
                return InputAdapterResult(
                    success=False,
                    error=f"Failed to read YAML file: {source}"
                )

            # Process template if specified
            if "template" in yaml_data:
                template_name = yaml_data.pop("template")
                try:
                    template_data = self.template_manager.load_template(template_name)
                    yaml_data = YAMLVariableSubstitution.merge_template(template_data, yaml_data)
                except ValueError as e:
                    return InputAdapterResult(
                        success=False,
                        error=f"Template error: {str(e)}"
                    )

            # Detect format: single video vs video set
            format_type = self.schema_validator.detect_format(yaml_data)

            # Validate YAML schema before processing
            validation_errors = self.schema_validator.validate_yaml_schema(yaml_data, format_type)
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


__all__ = ["YAMLFileAdapter", "YAMLValidationError"]
