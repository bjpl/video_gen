"""YAML path resolution and variable interpolation.

This module handles secure file path resolution and variable substitution
in YAML templates.
"""

from pathlib import Path
from typing import Any, Dict
import re
import yaml


class YAMLPathResolver:
    """Handles secure path resolution for YAML files."""

    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10_000_000

    # System directories to block (security)
    SYSTEM_DIRS = ['/etc', '/sys', '/proc', '/root', '/boot', '/var', '/usr', '/bin', '/sbin']

    def __init__(self, project_root: Path, test_mode: bool = False):
        """Initialize path resolver.

        Args:
            project_root: Root directory for path resolution
            test_mode: If True, bypass security checks for testing
        """
        self.project_root = project_root
        self.test_mode = test_mode
        self.supported_formats = {".yaml", ".yml"}

    async def read_yaml_file(self, source: Any) -> Dict[str, Any]:
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
                self.project_root,  # Project directory
                Path("/tmp"),  # System temp directory (for uploads)
                self.project_root / "uploads"  # Project uploads directory
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


class YAMLVariableSubstitution:
    """Handles variable substitution in YAML templates."""

    @staticmethod
    def substitute_variables(text: str, variables: Dict[str, Any]) -> str:
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

    @staticmethod
    def substitute_all_variables(data: Any, variables: Dict[str, Any]) -> Any:
        """Recursively substitute variables in all strings in data structure.

        Args:
            data: Data structure (dict, list, str, etc.)
            variables: Variable substitution dictionary

        Returns:
            Data with all variables substituted
        """
        if isinstance(data, dict):
            return {
                k: YAMLVariableSubstitution.substitute_all_variables(v, variables)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [
                YAMLVariableSubstitution.substitute_all_variables(item, variables)
                for item in data
            ]
        elif isinstance(data, str):
            return YAMLVariableSubstitution.substitute_variables(data, variables)
        else:
            return data

    @staticmethod
    def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
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
                result[key] = YAMLVariableSubstitution.deep_merge(result[key], value)
            elif key in result and isinstance(result[key], list) and isinstance(value, list):
                # Extend lists (could also replace - depends on use case)
                result[key] = result[key] + value
            else:
                # Override value
                result[key] = value

        return result

    @staticmethod
    def merge_template(
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
        merged = YAMLVariableSubstitution.deep_merge(template_data.copy(), override_data)

        # Recursively substitute variables
        return YAMLVariableSubstitution.substitute_all_variables(merged, variables)


__all__ = ["YAMLPathResolver", "YAMLVariableSubstitution"]
