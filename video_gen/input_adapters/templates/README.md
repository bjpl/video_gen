# YAML Video Templates

This directory contains reusable YAML templates for rapid video creation.

## Overview

Templates provide pre-structured video configurations with variable placeholders. This allows you to:
- Create videos quickly using proven patterns
- Maintain consistency across similar videos
- Focus on content rather than structure
- Customize templates to fit your needs

## Available Templates

### 1. **tutorial.yaml** - Educational Tutorial Videos
Comprehensive template for creating educational tutorials with learning objectives, examples, and checkpoints.

**Best for:**
- Software tutorials
- How-to guides
- Step-by-step instructions
- Educational content

**Key sections:**
- Title and introduction
- Learning objectives
- Core concepts
- Practical examples
- Problem/solution pairs
- Checkpoint reviews
- Outro with next steps

### 2. **presentation.yaml** - Business Presentations
Professional template for business presentations and talks.

**Best for:**
- Sales pitches
- Business proposals
- Conference talks
- Product launches

**Key sections:**
- Title with presenter info
- Agenda/overview
- Problem statement
- Solution/proposal
- Key takeaways
- Call to action

### 3. **intro.yaml** - Short Intro Videos
Quick, punchy template for channel intros or topic introductions.

**Best for:**
- Channel introductions
- Video series openers
- Quick announcements
- Product teasers

**Key sections:**
- Hook/attention grabber
- Main title and tagline
- Quick overview
- Call to action (2-4 scenes total)

### 4. **course_lesson.yaml** - Structured Course Lessons
Comprehensive template for structured course lessons with prerequisites, exercises, and assessments.

**Best for:**
- Online courses
- Training modules
- Educational series
- Certification programs

**Key sections:**
- Lesson introduction
- Prerequisites check
- Learning objectives
- Main content
- Live demonstration
- Quiz/assessment
- Practice exercise
- Summary and next lesson preview

### 5. **documentation.yaml** - Technical Documentation
Template for creating video documentation of software, APIs, or technical topics.

**Best for:**
- API documentation
- Software guides
- Feature demonstrations
- Technical onboarding

**Key sections:**
- Overview
- Installation/setup
- Basic usage
- Advanced features
- Code examples
- Troubleshooting
- Additional resources

## Usage

### Basic Usage

1. Create a YAML file that references a template:

```yaml
# my_video.yaml
template: tutorial

variables:
  video_id: my_tutorial
  title: My Amazing Tutorial
  topic: Python Programming
  # ... other variables
```

2. Generate your video:

```bash
python scripts/create_video.py --document my_video.yaml
```

### Variable Syntax

Templates support two types of variable placeholders:

#### Simple Variables
```yaml
title: ${title}
```

#### Variables with Defaults
```yaml
accent_color: ${accent_color|blue}
```

If `accent_color` is not provided, `blue` will be used.

### Template Overrides

You can override any part of the template:

```yaml
template: tutorial

variables:
  # ... your variables

# Override template settings
accent_color: purple
voice: female

# Add custom scenes (appended to template scenes)
scenes:
  - scene_id: bonus
    scene_type: list
    narration: Here's a bonus section
    visual_content:
      header: Bonus Content
      items:
        - Extra tip 1
        - Extra tip 2
```

## Complete Example

See `/examples/template_usage_example.yaml` for a complete working example.

## Creating Custom Templates

To create your own template:

1. Create a new `.yaml` file in this directory
2. Use `${variable_name}` or `${variable_name|default}` for placeholders
3. Structure your scenes as needed
4. Add descriptive comments at the top

Example custom template:

```yaml
# My Custom Template
# Description of what this template is for
#
# Variables:
#   ${title} - Video title
#   ${topic} - Main topic

video_id: ${video_id}
title: ${title}
description: ${description}
accent_color: ${accent_color|blue}

scenes:
  - scene_id: intro
    scene_type: title
    narration: Welcome to ${title}
    visual_content:
      title: ${title}
      subtitle: ${subtitle|Learn More}

  # ... more scenes
```

## Tips

1. **Start with a template**: Don't reinvent the wheel. Use an existing template as a starting point.

2. **Provide all required variables**: Check the template comments for required variables.

3. **Use defaults wisely**: Templates provide sensible defaults, but customize for your brand.

4. **Test incrementally**: Start with basic variables and add complexity gradually.

5. **Mix and match**: You can use a template and add custom scenes for unique content.

## Listing Available Templates

To see all available templates programmatically:

```python
from video_gen.input_adapters.yaml_file import YAMLFileAdapter

adapter = YAMLFileAdapter()
templates = adapter.list_templates()

for template in templates:
    print(f"{template['name']}: {template['description']}")
```

## Template Structure

All templates follow this general structure:

```yaml
# Template metadata (comments)
# - Description
# - Variables list
# - Use cases

# Video configuration
video_id: ${video_id}
title: ${title}
description: ${description}
accent_color: ${accent_color|blue}
voice: ${voice|male}

# Scenes array
scenes:
  - scene_id: unique_id
    scene_type: title|command|list|outro|etc
    narration: ${variable_name}
    visual_content:
      # Scene-specific visual content
    min_duration: 3.0  # optional
    max_duration: 15.0  # optional
```

## Supported Scene Types

- `title` - Title cards with headers and subtitles
- `command` - Terminal commands or code
- `list` - Bullet points or numbered lists
- `outro` - Closing scenes
- `code_comparison` - Before/after code comparison
- `quote` - Highlighted quotes
- `learning_objectives` - Learning objectives list
- `problem` - Problem statement
- `solution` - Solution presentation
- `checkpoint` - Knowledge check/review
- `quiz` - Quiz questions
- `exercise` - Practice exercises

## Support

For questions or issues with templates, please refer to the main project documentation or create an issue on GitHub.
