# YAML Template System

**Status:** ✅ Completed and Tested
**Date:** October 11, 2025
**Test Coverage:** 23 comprehensive tests (100% passing)

## Overview

The YAML Template System provides reusable video configuration templates with variable substitution, enabling rapid video creation using proven patterns while maintaining consistency.

## Features

### 1. Template Loading
- **Template Discovery:** Automatic discovery of templates in `video_gen/input_adapters/templates/`
- **Caching:** Templates are cached after first load for performance
- **Error Handling:** Clear error messages for missing or invalid templates

### 2. Variable Substitution
Supports two variable syntax patterns:

```yaml
# Simple variable
title: ${video_title}

# Variable with default fallback
accent_color: ${color|blue}
```

**Features:**
- Recursive substitution in nested structures (dicts, lists)
- Type preservation (numbers, booleans, nulls remain unchanged)
- Default values for missing variables
- Support for special characters and numeric values

### 3. Template Merging
- **Deep Merge:** Nested dictionaries are merged intelligently
- **List Extension:** Lists from override are appended to template lists
- **Override Priority:** User values always take precedence over template values
- **Variable Extraction:** `variables` key is automatically extracted and applied

### 4. Template Inheritance
Users can:
- Reference a base template
- Provide custom variable values
- Override template settings
- Add custom scenes beyond template structure

## Available Templates

### 1. **tutorial.yaml** (8 scenes)
Educational tutorial with learning objectives, examples, and checkpoints.

**Variables:** video_id, title, topic, subtitle, objectives, concepts, examples, problem/solution descriptions

**Use Cases:** Software tutorials, how-to guides, educational content

### 2. **presentation.yaml** (6 scenes)
Professional business presentations and talks.

**Variables:** video_id, title, presenter, sections, problem/solution, key_points, cta_message

**Use Cases:** Sales pitches, business proposals, conference talks

### 3. **intro.yaml** (4 scenes)
Short, punchy intro videos (2-4 scenes).

**Variables:** video_id, title, tagline, hook, features, cta_message

**Use Cases:** Channel intros, video series openers, product teasers

### 4. **course_lesson.yaml** (10 scenes)
Comprehensive course lessons with exercises and assessments.

**Variables:** course_name, lesson_number, lesson_title, prerequisites, objectives, quiz_question

**Use Cases:** Online courses, training modules, certification programs

### 5. **documentation.yaml** (8 scenes)
Technical documentation of software, APIs, or tools.

**Variables:** project_name, feature, version, setup_commands, code_examples

**Use Cases:** API documentation, software guides, feature demonstrations

## Usage

### Basic Template Usage

```yaml
# my_video.yaml
template: tutorial

variables:
  video_id: python_basics
  title: Python Basics Tutorial
  topic: Python Programming
  objectives:
    - Understand Python syntax
    - Write simple programs
  # ... more variables
```

### With Overrides

```yaml
template: presentation

variables:
  video_id: sales_pitch
  title: Q4 Results
  # ... variables

# Override template settings
accent_color: purple
voice: female

# Add custom scenes
scenes:
  - scene_id: bonus
    scene_type: list
    narration: Bonus content
    visual_content:
      header: Extra Tips
      items: [...]
```

### Generate Video

```bash
python scripts/create_video.py --document my_video.yaml
```

## API

### YAMLFileAdapter Methods

#### `list_templates() -> List[Dict[str, str]]`
Lists all available templates with descriptions.

```python
adapter = YAMLFileAdapter()
templates = adapter.list_templates()
# Returns: [{"name": "tutorial", "description": "..."}, ...]
```

#### `_load_template(template_name: str) -> Dict[str, Any]`
Loads a template by name (internal method).

#### `_substitute_variables(text: str, variables: Dict) -> str`
Substitutes variables in a string (internal method).

#### `_merge_template(template: Dict, override: Dict) -> Dict`
Merges template with overrides and applies variable substitution (internal method).

## Implementation Details

### File Structure

```
video_gen/
  input_adapters/
    templates/
      README.md              # Template documentation
      tutorial.yaml          # Tutorial template
      presentation.yaml      # Presentation template
      intro.yaml            # Intro template
      course_lesson.yaml    # Course lesson template
      documentation.yaml    # Documentation template
    yaml_file.py            # YAMLFileAdapter with template support
tests/
  test_yaml_templates.py    # 23 comprehensive tests
examples/
  template_usage_example.yaml  # Complete working example
  demo_templates.py         # Demonstration script
docs/
  YAML_TEMPLATE_SYSTEM.md   # This file
```

### Code Architecture

**Template Processing Flow:**
1. User YAML file specifies `template: name`
2. `adapt()` detects template reference
3. Template loaded from `templates/` directory (with caching)
4. Variables extracted from user YAML
5. Template and user data merged (deep merge)
6. Variables substituted recursively
7. Standard YAML processing continues

**Key Methods:**
- `_get_template_dir()` - Returns template directory path
- `_load_template()` - Loads and caches template
- `_substitute_variables()` - Variable substitution with ${var} syntax
- `_merge_template()` - Deep merge with variable substitution
- `_deep_merge()` - Recursive dictionary merging
- `_substitute_all_variables()` - Recursive variable substitution

### Security Considerations

✅ **Safe:** Uses existing YAML security infrastructure
- Templates go through same validation as regular YAML files
- `yaml.safe_load()` prevents code execution
- Path traversal protection still applies
- File size limits enforced
- Schema validation after template processing

## Testing

### Test Coverage: 23 Tests (100% Passing)

**Test Categories:**

1. **Template Loading (4 tests)**
   - List available templates
   - Load specific template
   - Handle missing templates
   - Template caching

2. **Variable Substitution (6 tests)**
   - Simple substitution
   - Variables with defaults
   - Multiple variables
   - Missing variables
   - Recursive substitution
   - Type preservation

3. **Template Merging (4 tests)**
   - Simple merge
   - Nested merge
   - List extension
   - Full merge with variables

4. **Integration (4 tests)**
   - Load YAML with template
   - Template with overrides
   - Invalid template handling
   - Custom scene addition

5. **Edge Cases (5 tests)**
   - Empty variables
   - Missing defaults
   - Special characters
   - Numeric values
   - None values

### Running Tests

```bash
# Run all template tests
python3 -m pytest tests/test_yaml_templates.py -v

# Run specific test class
python3 -m pytest tests/test_yaml_templates.py::TestTemplateLoading -v

# Run with coverage
python3 -m pytest tests/test_yaml_templates.py --cov=video_gen.input_adapters.yaml_file
```

## Examples

### Example 1: Quick Tutorial Video

```yaml
template: tutorial

variables:
  video_id: git_basics
  title: Git Basics for Beginners
  topic: Git Version Control
  objectives:
    - Understand Git fundamentals
    - Create repositories
  concepts:
    - Repository initialization
    - Staging changes
  examples:
    - git init
    - git add .
  # ... more variables
```

### Example 2: Product Presentation

```yaml
template: presentation

variables:
  video_id: product_launch
  title: New Product Launch
  presenter: Jane Doe
  problem_description: Current tools are too complex
  solution_description: Our simplified approach
  key_points:
    - 50% faster workflow
    - Easy to learn
```

### Example 3: Channel Intro

```yaml
template: intro

variables:
  video_id: channel_intro
  title: Welcome to TechTalks
  tagline: Learn. Code. Build.
  hook: Want to level up your coding skills?
  features:
    - Expert tutorials
    - Real-world projects
    - Community support
```

## Performance

- **Template Loading:** ~5-10ms first load, <1ms cached
- **Variable Substitution:** O(n) where n = string length
- **Template Merging:** O(m) where m = number of dict keys
- **Memory:** Templates cached in memory (typically <100KB per template)

## Future Enhancements

Potential future additions:
- [ ] Conditional sections (if/else in templates)
- [ ] Template inheritance (extend other templates)
- [ ] Template validation schema
- [ ] Custom template directories
- [ ] Template versioning
- [ ] Template marketplace/sharing

## Related Documentation

- **Template Usage Guide:** `video_gen/input_adapters/templates/README.md`
- **Working Example:** `examples/template_usage_example.yaml`
- **Demo Script:** `examples/demo_templates.py`
- **API Reference:** Main project API documentation
- **Test Suite:** `tests/test_yaml_templates.py`

## Support

For questions or issues:
1. Check the template README: `video_gen/input_adapters/templates/README.md`
2. Review examples: `examples/template_usage_example.yaml`
3. Run demo script: `python3 examples/demo_templates.py`
4. Check test suite for usage patterns: `tests/test_yaml_templates.py`

---

**Implementation Status:** ✅ Complete
**Production Ready:** Yes
**Breaking Changes:** None (fully backward compatible)
