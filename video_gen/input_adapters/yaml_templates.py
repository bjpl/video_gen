"""YAML template loading and management.

This module handles loading, caching, and listing of reusable YAML templates
with variable placeholder support.
"""

from pathlib import Path
from typing import Any, Dict, List
import yaml


class YAMLTemplateManager:
    """Manages YAML templates for video configurations."""

    def __init__(self, template_dir: Path):
        """Initialize template manager.

        Args:
            template_dir: Directory containing template files
        """
        self.template_dir = template_dir
        self._template_cache = {}  # Cache loaded templates for performance

    def load_template(self, template_name: str) -> Dict[str, Any]:
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

        template_path = self.template_dir / f"{template_name}.yaml"

        if not template_path.exists():
            available = [f.stem for f in self.template_dir.glob("*.yaml")]
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

    def list_templates(self) -> List[Dict[str, str]]:
        """List all available templates with their descriptions.

        Returns:
            List of template info dictionaries with 'name' and 'description' keys
        """
        templates = []

        for template_path in sorted(self.template_dir.glob("*.yaml")):
            template_name = template_path.stem
            try:
                template_data = self.load_template(template_name)

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


__all__ = ["YAMLTemplateManager"]
