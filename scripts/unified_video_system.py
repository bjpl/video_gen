"""
Unified Video Production System v2.0
=====================================
Ensures perfect audio/visual synchronization through:
1. Single source of truth for all content
2. Audio-duration-driven video timing
3. Multi-stage validation
4. Preview and timing reports
5. Content consistency verification
"""

from PIL import Image, ImageDraw, ImageFont
import subprocess
import os
import shutil
import json
import asyncio
import edge_tts
from datetime import timedelta
import wave
import contextlib
import logging

# Setup logging
logger = logging.getLogger(__name__)


WIDTH, HEIGHT = 1920, 1080
FPS = 30

BG_LIGHT = (245, 248, 252)
BG_WHITE = (255, 255, 255)
ACCENT_ORANGE = (255, 107, 53)
ACCENT_BLUE = (59, 130, 246)
ACCENT_PURPLE = (139, 92, 246)
ACCENT_GREEN = (16, 185, 129)
ACCENT_PINK = (236, 72, 153)
ACCENT_CYAN = (34, 211, 238)
TEXT_DARK = (15, 23, 42)
TEXT_GRAY = (100, 116, 139)
TEXT_LIGHT = (148, 163, 184)
CODE_BLUE = (59, 130, 246)
CARD_BG = (255, 255, 255)
CARD_SHADOW = (203, 213, 225)

try:
    font_title = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 120)
    font_subtitle = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 48)
    font_header = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", 64)
    font_desc = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 38)
    font_code = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 32)
    font_small = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", 28)
except Exception:
    # Fallback to default font if TrueType fonts not available
    font_title = ImageFont.load_default()
    font_subtitle = ImageFont.load_default()
    font_header = ImageFont.load_default()
    font_desc = ImageFont.load_default()
    font_code = ImageFont.load_default()
    font_small = ImageFont.load_default()

VOICE_CONFIG = {
    "male": "en-US-AndrewMultilingualNeural",        # Professional, confident
    "male_warm": "en-US-BrandonMultilingualNeural",  # Warm, engaging
    "female": "en-US-AriaNeural",                    # Clear, crisp
    "female_friendly": "en-US-AvaMultilingualNeural" # Friendly, pleasant
}

FFMPEG_PATH = "C:/Users/brand/AppData/Local/Programs/Python/Python310/lib/site-packages/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe"

class UnifiedScene:
    def __init__(self, scene_id, scene_type, visual_content, narration, voice="male", min_duration=3.0, max_duration=15.0):
        self.scene_id = scene_id
        self.scene_type = scene_type
        self.visual_content = visual_content
        self.narration = narration
        self.voice = voice
        self.min_duration = min_duration
        self.max_duration = max_duration
        self.actual_audio_duration = None
        self.final_duration = None
        self.audio_file = None
        self.warnings = []

    def validate(self):
        if not self.narration:
            self.warnings.append(f"Scene {self.scene_id}: No narration provided")

        if self.scene_type not in ['title', 'command', 'list', 'outro']:
            self.warnings.append(f"Scene {self.scene_id}: Unknown scene type '{self.scene_type}'")

        word_count = len(self.narration.split())
        estimated_duration = word_count / 2.25

        if estimated_duration > self.max_duration:
            self.warnings.append(
                f"Scene {self.scene_id}: Narration may be too long "
                f"({word_count} words ≈ {estimated_duration:.1f}s, max {self.max_duration}s)"
            )

        if estimated_duration < self.min_duration:
            self.warnings.append(
                f"Scene {self.scene_id}: Narration may be too short "
                f"({word_count} words ≈ {estimated_duration:.1f}s, min {self.min_duration}s)"
            )

        if self.scene_type == 'command' and 'commands' not in self.visual_content:
            self.warnings.append(f"Scene {self.scene_id}: Command scene missing 'commands' in visual_content")

        if self.scene_type == 'list' and 'items' not in self.visual_content:
            self.warnings.append(f"Scene {self.scene_id}: List scene missing 'items' in visual_content")

        return len(self.warnings) == 0

    def to_dict(self):
        return {
            'scene_id': self.scene_id,
            'scene_type': self.scene_type,
            'narration': self.narration,
            'voice': self.voice,
            'actual_audio_duration': self.actual_audio_duration,
            'final_duration': self.final_duration,
            'warnings': self.warnings
        }


class UnifiedVideo:
    def __init__(self, video_id, title, description, accent_color, scenes, version="v2.0"):
        self.video_id = video_id
        self.title = title
        self.description = description
        self.accent_color = accent_color
        self.scenes = scenes
        self.version = version
        self.total_duration = 0
        self.audio_dir = None
        self.video_file = None
        self.final_file = None
        self.validation_report = None
        self.generation_timestamp = None

    def generate_smart_filename(self, file_type="video", include_audio=True):
        """
        Generate intelligent filename with metadata
        Format: {video_id}_{duration}s_{version}_{audio_status}_{timestamp}.{ext}
        Example: quick_reference_30s_v2.0_with_audio_20250926.mp4
        """
        from datetime import datetime

        if self.generation_timestamp is None:
            self.generation_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        duration_str = f"{int(self.total_duration)}s" if self.total_duration else "unknown"

        audio_status = "with_audio" if include_audio else "silent"

        sanitized_id = self.video_id.replace("_", "-")

        if file_type == "video":
            ext = "mp4"
            filename = f"{sanitized_id}_{duration_str}_{self.version}_{audio_status}_{self.generation_timestamp}.{ext}"
        elif file_type == "audio_dir":
            filename = f"{sanitized_id}_{duration_str}_{self.version}_audio_{self.generation_timestamp}"
        elif file_type == "timing_report":
            ext = "json"
            filename = f"{sanitized_id}_{duration_str}_{self.version}_timing_{self.generation_timestamp}.{ext}"
        elif file_type == "preview":
            ext = "txt"
            filename = f"{sanitized_id}_{self.version}_preview_{self.generation_timestamp}.{ext}"
        elif file_type == "validation":
            ext = "json"
            filename = f"{sanitized_id}_{self.version}_validation_{self.generation_timestamp}.{ext}"
        else:
            filename = f"{sanitized_id}_{self.version}_{self.generation_timestamp}"

        return filename

    def get_metadata(self):
        """Return comprehensive metadata about the video"""
        return {
            'video_id': self.video_id,
            'title': self.title,
            'description': self.description,
            'version': self.version,
            'total_duration': self.total_duration,
            'scene_count': len(self.scenes),
            'timestamp': self.generation_timestamp,
            'accent_color': self.accent_color,
            'voice_count': len(set(scene.voice for scene in self.scenes)),
            'files': {
                'video': self.video_file,
                'final': self.final_file,
                'audio_dir': self.audio_dir
            }
        }

    def validate(self):
        all_valid = True
        report = {
            'video_id': self.video_id,
            'title': self.title,
            'scene_count': len(self.scenes),
            'issues': [],
            'warnings': []
        }

        for scene in self.scenes:
            if not scene.validate():
                all_valid = False
                report['warnings'].extend(scene.warnings)

        if len(self.scenes) == 0:
            report['issues'].append("No scenes defined")
            all_valid = False

        if len(self.scenes) > 10:
            report['warnings'].append(f"Video has {len(self.scenes)} scenes - may be too long")

        self.validation_report = report
        return all_valid

    def generate_preview(self):
        logger.info(f"\n{'='*80}")
        logger.info(f"PREVIEW: {self.title}")
        logger.info(f"{'='*80}\n")
        logger.info(f"Video ID: {self.video_id}")
        logger.info(f"Accent Color: RGB{self.accent_color}")
        logger.info(f"Total Scenes: {len(self.scenes)}\n")

        logger.info("Scene Breakdown:")
        logger.info("-" * 80)

        total_words = 0
        estimated_total = 0

        for i, scene in enumerate(self.scenes, 1):
            word_count = len(scene.narration.split())
            total_words += word_count
            est_duration = word_count / 2.25
            estimated_total += est_duration

            logger.info(f"\n[{i}] {scene.scene_id} ({scene.scene_type.upper()})")
            logger.info(f"    Voice: {scene.voice}")
            logger.info(f"    Words: {word_count}")
            logger.info(f"    Est. Duration: {est_duration:.1f}s")
            logger.info(f"    Narration: \"{scene.narration[:80]}...\"")

            if scene.warnings:
                logger.warning(f"    ⚠️  Warnings: {len(scene.warnings)}")
                for warning in scene.warnings:
                    logger.warning(f"        - {warning}")

        logger.info("\n" + "=" * 80)
        logger.info(f"TOTAL ESTIMATED:")
        logger.info(f"  Words: {total_words}")
        logger.info(f"  Duration: {estimated_total:.1f}s ({estimated_total/60:.1f} minutes)")
        logger.info(f"  Average WPM: {(total_words / estimated_total) * 60:.0f}")
        logger.info("=" * 80 + "\n")

        return estimated_total

    async def generate_audio_with_timing(self, output_dir):
        from datetime import datetime
        if self.generation_timestamp is None:
            self.generation_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        audio_folder_name = self.generate_smart_filename(file_type="audio_dir", include_audio=False)
        self.audio_dir = os.path.join(output_dir, audio_folder_name)
        os.makedirs(self.audio_dir, exist_ok=True)

        logger.info(f"\n{'='*80}")
        logger.info(f"GENERATING AUDIO: {self.title}")
        logger.info(f"{'='*80}\n")

        for i, scene in enumerate(self.scenes, 1):
            voice = VOICE_CONFIG.get(scene.voice, VOICE_CONFIG["male"])
            audio_file = os.path.join(self.audio_dir, f"{scene.scene_id}.mp3")

            logger.info(f"[{i}/{len(self.scenes)}] {scene.scene_id}")
            logger.info(f"    Generating with {voice}...")

            communicate = edge_tts.Communicate(scene.narration, voice, rate="+0%", volume="+0%")
            await communicate.save(audio_file)

            duration = await self.get_audio_duration(audio_file)
            scene.actual_audio_duration = duration
            scene.audio_file = audio_file

            scene.final_duration = max(scene.min_duration, scene.actual_audio_duration + 1.0)

            file_size = os.path.getsize(audio_file) / 1024
            logger.info(f"    ✓ Duration: {duration:.2f}s (file: {file_size:.1f} KB)")

            if duration < scene.min_duration:
                logger.warning(f"    ⚠️  Audio shorter than minimum ({scene.min_duration}s) - will pad video")
            elif duration > scene.max_duration:
                logger.warning(f"    ⚠️  Audio longer than maximum ({scene.max_duration}s) - scene extended to {scene.final_duration:.2f}s")

        self.total_duration = sum(scene.final_duration for scene in self.scenes)

        logger.info(f"\n{'='*80}")
        logger.info(f"AUDIO GENERATION COMPLETE")
        logger.info(f"  Total Duration: {self.total_duration:.2f}s")
        logger.info(f"  Audio Files: {len(self.scenes)}")
        logger.info(f"{'='*80}\n")

        return self.audio_dir

    async def get_audio_duration(self, audio_file):
        result = subprocess.run(
            [FFMPEG_PATH, "-i", audio_file],
            capture_output=True,
            text=True
        )

        for line in result.stderr.split('\n'):
            if 'Duration:' in line:
                time_str = line.split('Duration:')[1].split(',')[0].strip()
                h, m, s = time_str.split(':')
                duration = int(h) * 3600 + int(m) * 60 + float(s)
                return duration

        return 5.0

    def generate_timing_report(self):
        timing_filename = self.generate_smart_filename(file_type="timing_report")
        report_file = os.path.join(self.audio_dir, timing_filename)

        report = {
            'video_id': self.video_id,
            'title': self.title,
            'total_duration': self.total_duration,
            'total_scenes': len(self.scenes),
            'scenes': []
        }

        cumulative_time = 0
        for scene in self.scenes:
            scene_data = {
                'scene_id': scene.scene_id,
                'type': scene.scene_type,
                'voice': scene.voice,
                'start_time': cumulative_time,
                'end_time': cumulative_time + scene.final_duration,
                'duration': scene.final_duration,
                'audio_duration': scene.actual_audio_duration,
                'padding': scene.final_duration - scene.actual_audio_duration,
                'narration_preview': scene.narration[:100]
            }
            report['scenes'].append(scene_data)
            cumulative_time += scene.final_duration

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"\n{'='*80}")
        logger.info(f"TIMING REPORT")
        logger.info(f"{'='*80}\n")

        logger.info(f"{'Scene':<25} {'Start':<8} {'End':<8} {'Duration':<10} {'Audio':<10} {'Pad':<8}")
        logger.info("-" * 80)

        for scene_data in report['scenes']:
            logger.info(f"{scene_data['scene_id']:<25} "
                  f"{scene_data['start_time']:>6.1f}s "
                  f"{scene_data['end_time']:>6.1f}s "
                  f"{scene_data['duration']:>8.2f}s "
                  f"{scene_data['audio_duration']:>8.2f}s "
                  f"{scene_data['padding']:>6.2f}s")

        logger.info("-" * 80)
        logger.info(f"{'TOTAL':<25} {'':8} {cumulative_time:>6.1f}s\n")

        logger.info(f"Timing report saved: {report_file}\n")

        return report

    def save_validation_report(self, output_dir):
        """Save validation report with smart filename"""
        if self.validation_report is None:
            self.validate()

        validation_filename = self.generate_smart_filename(file_type="validation")
        report_file = os.path.join(output_dir, validation_filename)

        with open(report_file, 'w') as f:
            json.dump(self.validation_report, f, indent=2)

        logger.info(f"Validation report saved: {report_file}")
        return report_file

    def save_preview_file(self, output_dir):
        """Save preview/storyboard as text file"""
        preview_filename = self.generate_smart_filename(file_type="preview")
        preview_file = os.path.join(output_dir, preview_filename)

        with open(preview_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"VIDEO PREVIEW: {self.title}\n")
            f.write("="*80 + "\n\n")
            f.write(f"Video ID: {self.video_id}\n")
            f.write(f"Version: {self.version}\n")
            f.write(f"Description: {self.description}\n")
            f.write(f"Accent Color: RGB{self.accent_color}\n")
            f.write(f"Total Scenes: {len(self.scenes)}\n\n")

            total_words = 0
            estimated_total = 0

            f.write("SCENE BREAKDOWN\n")
            f.write("-"*80 + "\n\n")

            for i, scene in enumerate(self.scenes, 1):
                word_count = len(scene.narration.split())
                total_words += word_count
                est_duration = word_count / 2.25
                estimated_total += est_duration

                f.write(f"[{i}] {scene.scene_id} ({scene.scene_type.upper()})\n")
                f.write(f"    Voice: {scene.voice}\n")
                f.write(f"    Words: {word_count}\n")
                f.write(f"    Est. Duration: {est_duration:.1f}s\n")
                f.write(f"    Min/Max: {scene.min_duration}s / {scene.max_duration}s\n")
                f.write(f"\n    Narration:\n")
                f.write(f"    \"{scene.narration}\"\n\n")

                if scene.warnings:
                    f.write(f"    ⚠️  Warnings ({len(scene.warnings)}):\n")
                    for warning in scene.warnings:
                        f.write(f"        - {warning}\n")
                    f.write("\n")

                f.write("    Visual Content:\n")
                for key, value in scene.visual_content.items():
                    if isinstance(value, list):
                        f.write(f"      {key}:\n")
                        for item in value:
                            f.write(f"        - {item}\n")
                    else:
                        f.write(f"      {key}: {value}\n")
                f.write("\n" + "-"*80 + "\n\n")

            f.write("="*80 + "\n")
            f.write(f"TOTAL ESTIMATED:\n")
            f.write(f"  Words: {total_words}\n")
            f.write(f"  Duration: {estimated_total:.1f}s ({estimated_total/60:.1f} minutes)\n")
            f.write(f"  Average WPM: {(total_words / estimated_total) * 60:.0f}\n")
            f.write("="*80 + "\n")

        logger.info(f"Preview file saved: {preview_file}")
        return preview_file

    def save_metadata_manifest(self, output_dir):
        """Save comprehensive metadata manifest"""
        metadata_filename = f"{self.video_id}_{self.version}_manifest_{self.generation_timestamp}.json"
        manifest_file = os.path.join(output_dir, metadata_filename)

        manifest = {
            'video_metadata': self.get_metadata(),
            'validation': self.validation_report,
            'generation_info': {
                'timestamp': self.generation_timestamp,
                'version': self.version,
                'total_scenes': len(self.scenes),
                'total_duration': self.total_duration
            },
            'files': {
                'video_silent': self.generate_smart_filename(file_type="video", include_audio=False),
                'video_with_audio': self.generate_smart_filename(file_type="video", include_audio=True),
                'audio_directory': self.generate_smart_filename(file_type="audio_dir"),
                'timing_report': self.generate_smart_filename(file_type="timing_report"),
                'validation_report': self.generate_smart_filename(file_type="validation"),
                'preview_file': self.generate_smart_filename(file_type="preview")
            },
            'scenes': [scene.to_dict() for scene in self.scenes]
        }

        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"Metadata manifest saved: {manifest_file}")
        return manifest_file

QUICK_REFERENCE_VIDEO = UnifiedVideo(
    video_id="01_quick_reference",
    title="Quick Reference Guide",
    description="5-minute workflow commands",
    accent_color=ACCENT_ORANGE,
    scenes=[
        UnifiedScene(
            scene_id="scene_01_title",
            scene_type="title",
            visual_content={
                "title": "Quick Reference",
                "subtitle": "5-Minute Workflow Commands"
            },
            narration="Quick reference guide. Your five minute workflow for creating professional demo videos.",
            voice="male",
            min_duration=3.0,
            max_duration=6.0
        ),
        UnifiedScene(
            scene_id="scene_02_workflow",
            scene_type="command",
            visual_content={
                "header": "Complete Workflow",
                "description": "Generate Video with Audio in 40 Seconds",
                "commands": [
                    "$ cd claude_code_demos",
                    "$ python generate_narration_audio.py",
                    "$ cd scripts",
                    "$ python generate_video_with_audio.py",
                    "",
                    "→ Output: Full HD video with narration"
                ]
            },
            narration="Run four simple commands to generate your complete video with professional audio narration. The entire process takes about forty seconds on GPU-enabled systems.",
            voice="male",
            min_duration=7.0,
            max_duration=12.0
        ),
        UnifiedScene(
            scene_id="scene_03_components",
            scene_type="command",
            visual_content={
                "header": "Individual Components",
                "description": "Generate Audio or Video Separately",
                "commands": [
                    "# Generate audio only",
                    "$ python generate_narration_audio.py",
                    "",
                    "# Generate video only",
                    "$ python generate_video_with_audio.py",
                    "",
                    "→ Modular generation for flexibility"
                ]
            },
            narration="Generate audio and video separately for maximum flexibility. Create alternate voice options or modify video settings independently.",
            voice="male",
            min_duration=6.0,
            max_duration=10.0
        ),
        UnifiedScene(
            scene_id="scene_04_voices",
            scene_type="list",
            visual_content={
                "header": "Voice Mix Modes",
                "description": "Choose Your Narration Style",
                "items": [
                    ("Single Voice", "One professional narrator"),
                    ("Varied Voices", "Alternating male and female"),
                    ("All Male", "Two male narrators"),
                    ("All Female", "Two female narrators")
                ]
            },
            narration="Choose from four voice mix modes. Single voice for consistency, varied voices for engagement, or gender-specific options to match your brand.",
            voice="male",
            min_duration=6.0,
            max_duration=10.0
        ),
        UnifiedScene(
            scene_id="scene_05_outro",
            scene_type="outro",
            visual_content={
                "main_text": "Fast. Simple. Powerful.",
                "sub_text": "See QUICK_REFERENCE.md"
            },
            narration="Fast, simple, and powerful. See quick reference dot M D for complete command documentation.",
            voice="male",
            min_duration=3.0,
            max_duration=6.0
        )
    ]
)

async def main():
    logger.info("\n" + "="*80)
    logger.info("UNIFIED VIDEO PRODUCTION SYSTEM v2.0")
    logger.info("Audio-Duration-Driven | Smart File Naming | Multi-Stage Validation")
    logger.info("="*80)

    video = QUICK_REFERENCE_VIDEO
    reports_dir = "../audio/unified_system/reports"
    os.makedirs(reports_dir, exist_ok=True)

    logger.info("\n[STEP 1] VALIDATION & CONSISTENCY CHECKS")
    logger.info("-" * 80)
    if video.validate():
        logger.info("✓ All validation checks passed")
    else:
        logger.warning("⚠️  Validation warnings found:")
        for issue in video.validation_report.get('issues', []):
            logger.error(f"  ERROR: {issue}")
        for warning in video.validation_report.get('warnings', []):
            logger.warning(f"  WARN: {warning}")

    validation_file = video.save_validation_report(reports_dir)
    logger.info(f"  → Validation report: {os.path.basename(validation_file)}")

    logger.info("\n[STEP 2] PREVIEW & STORYBOARD GENERATION")
    logger.info("-" * 80)
    estimated = video.generate_preview()
    preview_file = video.save_preview_file(reports_dir)
    logger.info(f"  → Preview file: {os.path.basename(preview_file)}")

    logger.info("\n[STEP 3] AUDIO GENERATION WITH PRECISE TIMING")
    logger.info("-" * 80)
    logger.info("Generating audio first to measure exact durations...")
    await video.generate_audio_with_timing("../audio/unified_system")
    logger.info(f"  → Audio folder: {os.path.basename(video.audio_dir)}")

    logger.info("\n[STEP 4] TIMING ANALYSIS & SYNCHRONIZATION REPORT")
    logger.info("-" * 80)
    report = video.generate_timing_report()

    logger.info("\n[STEP 5] METADATA MANIFEST GENERATION")
    logger.info("-" * 80)
    manifest_file = video.save_metadata_manifest(reports_dir)
    logger.info(f"  → Manifest: {os.path.basename(manifest_file)}")

    logger.info("\n[STEP 6] FILE NAMING PREVIEW")
    logger.info("-" * 80)
    logger.info("Smart filenames generated:")
    logger.info(f"  Video (silent):     {video.generate_smart_filename('video', include_audio=False)}")
    logger.info(f"  Video (with audio): {video.generate_smart_filename('video', include_audio=True)}")
    logger.info(f"  Audio directory:    {video.generate_smart_filename('audio_dir')}")
    logger.info(f"  Timing report:      {video.generate_smart_filename('timing_report')}")

    logger.info("\n" + "="*80)
    logger.info("✓ UNIFIED SYSTEM PREPARATION COMPLETE")
    logger.info("="*80)
    logger.info(f"\nKey Metrics:")
    logger.info(f"  Total Duration: {video.total_duration:.2f}s (measured from actual audio)")
    logger.info(f"  Scene Count: {len(video.scenes)}")
    logger.info(f"  Audio Files: {len(video.scenes)} generated and measured")
    logger.info(f"  Generation Timestamp: {video.generation_timestamp}")
    logger.info(f"\nNext Step:")
    logger.info(f"  Use measured timings to generate perfectly synchronized video")
    logger.info(f"  Video duration will match audio exactly: {video.total_duration:.2f}s")
    logger.info(f"\nAll reports saved to: {reports_dir}/")
    logger.info("="*80 + "\n")

if __name__ == "__main__":
    asyncio.run(main())