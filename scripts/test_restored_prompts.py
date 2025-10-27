#!/usr/bin/env python3
"""Test script for restored OLD prompts.

This script tests the restored prompts from commit 31e0299c to verify they
produce better, more constrained technical narration.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from video_gen.script_generator.ai_enhancer import AIScriptEnhancer


async def test_prompt_comparison():
    """Test OLD prompts vs NEW prompts side-by-side."""

    # Check for API key
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print("❌ ANTHROPIC_API_KEY not set")
        print("   Set it with: export ANTHROPIC_API_KEY=your_key_here")
        return

    print("="*80)
    print("TESTING RESTORED OLD PROMPTS (commit 31e0299c)")
    print("="*80)
    print()

    # Initialize enhancer
    enhancer = AIScriptEnhancer(api_key=api_key)

    # Test cases for different scene types
    test_cases = [
        {
            'name': 'Title Scene',
            'scene_type': 'title',
            'context': {
                'title': 'Video Generation System',
                'subtitle': 'Professional video creation from documentation',
                'key_message': 'Create videos automatically',
                'scene_position': 0,
                'total_scenes': 6
            },
            'original_script': 'Video Generation System'
        },
        {
            'name': 'Command Scene',
            'scene_type': 'command',
            'context': {
                'topic': 'Installation',
                'header': 'Install Dependencies',
                'commands': ['pip install -r requirements.txt', 'python setup.py install'],
                'key_points': ['Install packages', 'Setup system'],
                'scene_position': 1,
                'total_scenes': 6
            },
            'original_script': 'Install the required packages'
        },
        {
            'name': 'List Scene',
            'scene_type': 'list',
            'context': {
                'topic': 'Key Features',
                'header': 'Main Features',
                'items': [
                    {'title': 'Document parsing', 'description': 'Parse markdown files'},
                    {'title': 'AI narration', 'description': 'Generate speech'},
                    {'title': 'Multi-language', 'description': '28+ languages'}
                ],
                'scene_position': 2,
                'total_scenes': 6
            },
            'original_script': 'The system provides multiple features'
        },
        {
            'name': 'Outro Scene',
            'scene_type': 'outro',
            'context': {
                'main_text': 'Learn More',
                'sub_text': 'See Documentation',
                'key_message': 'Visit docs for complete guide',
                'scene_position': 5,
                'total_scenes': 6
            },
            'original_script': 'Thank you for watching'
        }
    ]

    # Test each case with OLD prompts
    print("Testing with OLD PROMPTS (use_old_prompts=True):")
    print("-" * 80)
    print()

    for test in test_cases:
        print(f"Scene: {test['name']}")
        print(f"Type: {test['scene_type']}")
        print(f"Original: \"{test['original_script']}\"")
        print()

        try:
            enhanced = await enhancer.enhance_script(
                script=test['original_script'],
                scene_type=test['scene_type'],
                context=test['context'],
                use_old_prompts=True  # Use OLD prompts
            )

            word_count = len(enhanced.split())
            print(f"✅ Enhanced: \"{enhanced}\"")
            print(f"   Word count: {word_count} words")
            print(f"   Target: 10-20 words for {test['scene_type']}")

            # Check for banned marketing words
            from video_gen.script_generator.prompt_templates import BANNED_MARKETING_WORDS
            found_banned = [w for w in BANNED_MARKETING_WORDS if w.lower() in enhanced.lower()]
            if found_banned:
                print(f"   ⚠️  Contains banned words: {', '.join(found_banned)}")
            else:
                print(f"   ✓ No banned marketing words")

        except Exception as e:
            print(f"❌ Error: {e}")

        print()
        print("-" * 80)
        print()

    # Print metrics
    print()
    print("="*80)
    print("AI USAGE METRICS")
    print("="*80)
    metrics = enhancer.metrics.get_summary()
    print(f"API Calls: {metrics['api_calls']}")
    print(f"Input Tokens: {metrics['input_tokens']:,}")
    print(f"Output Tokens: {metrics['output_tokens']:,}")
    print(f"Estimated Cost: ${metrics['estimated_cost_usd']:.4f}")
    print(f"Success Rate: {metrics['success_rate']:.1f}%")
    print()

    print("="*80)
    print("TEST COMPLETE")
    print("="*80)
    print()
    print("Next steps:")
    print("1. Review the enhanced narration above")
    print("2. Check word counts (should be 10-25 words)")
    print("3. Verify no marketing language")
    print("4. Compare to previous outputs if available")
    print()


if __name__ == '__main__':
    asyncio.run(test_prompt_comparison())
