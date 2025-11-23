#!/usr/bin/env python3
"""
Unified CLI for Video Generation
=================================
One command to rule them all - complete video generation from any source.

Usage:
    python -m scripts.video_gen_cli create --from <source> [options]
    python -m scripts.video_gen_cli status <task_id>
    python -m scripts.video_gen_cli list
"""

import click
import asyncio
from pathlib import Path
from typing import Optional
import json
from datetime import datetime

from video_gen.pipeline import get_pipeline, TaskStatus
from video_gen.shared.models import InputConfig


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Video Generation CLI - Create videos from any source."""
    pass


@cli.command()
@click.option(
    "--from",
    "source",
    required=True,
    help="Source file or URL (document, YAML, YouTube URL)"
)
@click.option(
    "--output",
    default="./videos",
    help="Output directory for generated videos"
)
@click.option(
    "--voice",
    default="en-US-ChristopherNeural",
    help="TTS voice to use"
)
@click.option(
    "--language",
    default="en",
    help="Content language code (en, es, fr, etc.)"
)
@click.option(
    "--color",
    default="blue",
    help="Accent color for visuals"
)
@click.option(
    "--async",
    "run_async",
    is_flag=True,
    help="Run asynchronously (returns task ID immediately)"
)
@click.option(
    "--task-id",
    help="Optional custom task ID"
)
def create(
    source: str,
    output: str,
    voice: str,
    language: str,
    color: str,
    run_async: bool,
    task_id: Optional[str]
):
    """Create video from source.

    Examples:
        # From document
        video-gen create --from README.md

        # From YAML
        video-gen create --from config.yaml --voice en-US-JennyNeural

        # From YouTube
        video-gen create --from https://youtube.com/watch?v=...

        # Async execution
        video-gen create --from doc.md --async
    """
    click.echo(f"🎬 Creating video from: {source}")

    # Detect input type
    input_type = _detect_input_type(source)
    click.echo(f"📝 Detected input type: {input_type}")

    # Create input config
    input_config = InputConfig(
        input_type=input_type,
        source=source,
        config={
            "voice": voice,
            "language": language,
            "color": color,
            "output_dir": output,
        }
    )

    # Get pipeline
    pipeline = get_pipeline()

    if run_async:
        # Async execution
        task_id = asyncio.run(pipeline.execute_async(input_config, task_id))
        click.echo(f"\n✅ Task started: {task_id}")
        click.echo(f"   Check status with: video-gen status {task_id}")
    else:
        # Sync execution with progress
        with click.progressbar(
            length=100,
            label="Generating video",
            show_eta=True
        ) as bar:
            # Track progress
            def update_progress(event):
                if hasattr(event, 'progress'):
                    bar.update(int(event.progress * 100))

            # Subscribe to progress events
            from video_gen.pipeline.events import EventType
            pipeline.event_emitter.subscribe(
                EventType.STAGE_PROGRESS,
                update_progress
            )

            # Execute
            result = asyncio.run(pipeline.execute(input_config, task_id))

        if result.success:
            click.echo(f"\n✅ Video created successfully!")
            click.echo(f"\n📹 Video: {result.video_path}")
            click.echo(f"⏱️  Duration: {result.total_duration:.2f}s")
            click.echo(f"🎞️  Scenes: {result.scene_count}")
            click.echo(f"⚡ Generation time: {result.generation_time:.2f}s")

            # Show output location
            click.echo(f"\n📁 Output directory: {result.video_path.parent}")
        else:
            click.echo(f"\n❌ Video generation failed:", err=True)
            for error in result.errors:
                click.echo(f"   - {error}", err=True)
            exit(1)


@cli.command()
@click.argument("task_id")
@click.option("--watch", is_flag=True, help="Watch status updates in real-time")
def status(task_id: str, watch: bool):
    """Check status of a video generation task.

    Examples:
        video-gen status task_abc123
        video-gen status task_abc123 --watch
    """
    pipeline = get_pipeline()

    if watch:
        # Watch mode - poll for updates
        click.echo(f"👀 Watching task: {task_id} (Ctrl+C to stop)\n")
        try:
            while True:
                task_state = pipeline.get_status(task_id)

                if not task_state:
                    click.echo(f"❌ Task not found: {task_id}")
                    break

                # Clear screen and show status
                click.clear()
                _display_task_status(task_state)

                if task_state.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                    break

                asyncio.run(asyncio.sleep(2))

        except KeyboardInterrupt:
            click.echo("\n\n👋 Stopped watching")
    else:
        # Single status check
        task_state = pipeline.get_status(task_id)

        if not task_state:
            click.echo(f"❌ Task not found: {task_id}")
            exit(1)

        _display_task_status(task_state)


@cli.command()
@click.option("--status", type=click.Choice(["all", "running", "completed", "failed"]), default="all")
@click.option("--limit", default=10, help="Maximum number of tasks to show")
def list(status: str, limit: int):
    """List all video generation tasks.

    Examples:
        video-gen list
        video-gen list --status running
        video-gen list --status completed --limit 5
    """
    pipeline = get_pipeline()

    # Convert status filter
    status_filter = None
    if status != "all":
        status_filter = TaskStatus[status.upper()]

    tasks = pipeline.list_tasks(status_filter)

    if not tasks:
        click.echo("No tasks found.")
        return

    # Limit results
    tasks = tasks[:limit]

    click.echo(f"\n📋 Tasks ({len(tasks)}):\n")

    for task in tasks:
        status_icon = {
            TaskStatus.PENDING: "⏳",
            TaskStatus.RUNNING: "▶️",
            TaskStatus.COMPLETED: "✅",
            TaskStatus.FAILED: "❌",
            TaskStatus.CANCELLED: "🚫",
        }.get(task.status, "❓")

        click.echo(f"{status_icon} {task.task_id}")
        click.echo(f"   Status: {task.status.value}")
        if task.current_stage:
            click.echo(f"   Stage: {task.current_stage}")
        if task.overall_progress:
            click.echo(f"   Progress: {task.overall_progress:.0%}")
        click.echo()


@cli.command()
@click.argument("task_id")
@click.confirmation_option(prompt="Are you sure you want to cancel this task?")
def cancel(task_id: str):
    """Cancel a running task.

    Examples:
        video-gen cancel task_abc123
    """
    pipeline = get_pipeline()

    if pipeline.cancel(task_id):
        click.echo(f"✅ Task cancelled: {task_id}")
    else:
        click.echo(f"❌ Could not cancel task: {task_id}")


@cli.command()
@click.option("--days", default=7, help="Delete tasks older than N days")
@click.confirmation_option(prompt="Are you sure you want to cleanup old tasks?")
def cleanup(days: int):
    """Clean up old task data.

    Examples:
        video-gen cleanup --days 7
    """
    pipeline = get_pipeline()
    pipeline.cleanup_old_tasks(days)
    click.echo(f"✅ Cleaned up tasks older than {days} days")


def _detect_input_type(source: str) -> str:
    """Detect input type from source."""
    source = source.lower()

    if source.startswith("http://") or source.startswith("https://"):
        if "youtube.com" in source or "youtu.be" in source:
            return "youtube"
        return "url"

    path = Path(source)
    if path.exists():
        suffix = path.suffix.lower()

        if suffix in [".yaml", ".yml"]:
            return "yaml"
        elif suffix in [".md", ".txt", ".rst", ".pdf"]:
            return "document"

    return "document"  # Default fallback


def _display_task_status(task_state):
    """Display formatted task status."""
    status_icons = {
        TaskStatus.PENDING: "⏳",
        TaskStatus.RUNNING: "▶️",
        TaskStatus.COMPLETED: "✅",
        TaskStatus.FAILED: "❌",
        TaskStatus.CANCELLED: "🚫",
    }

    icon = status_icons.get(task_state.status, "❓")

    click.echo(f"{icon} Task: {task_state.task_id}")
    click.echo(f"Status: {task_state.status.value}")

    if task_state.current_stage:
        click.echo(f"Current Stage: {task_state.current_stage}")

    if task_state.overall_progress:
        progress_bar = "█" * int(task_state.overall_progress * 20)
        progress_bar += "░" * (20 - len(progress_bar))
        click.echo(f"Progress: [{progress_bar}] {task_state.overall_progress:.0%}")

    # Show completed stages
    completed = task_state.get_completed_stages()
    if completed:
        click.echo(f"\n✅ Completed stages ({len(completed)}):")
        for stage in completed:
            click.echo(f"   - {stage}")

    # Show errors
    if task_state.errors:
        click.echo(f"\n❌ Errors:")
        for error in task_state.errors:
            click.echo(f"   - {error}")

    # Show result if completed
    if task_state.result:
        click.echo(f"\n📹 Result:")
        result = task_state.result
        if "video_path" in result:
            click.echo(f"   Video: {result['video_path']}")
        if "total_duration" in result:
            click.echo(f"   Duration: {result['total_duration']:.2f}s")
        if "scene_count" in result:
            click.echo(f"   Scenes: {result['scene_count']}")


if __name__ == "__main__":
    cli()
