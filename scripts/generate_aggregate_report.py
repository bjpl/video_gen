"""
Aggregate Report Generator for Multiple Videos
==============================================
Quickly review health of 10-15 videos without reading individual reports.
"""

import json
import os
from datetime import datetime
from pathlib import Path

def generate_aggregate_dashboard(audio_base_dir):
    """Generate single dashboard for all videos"""

    reports_dir = os.path.join(audio_base_dir, 'reports')

    # Find all timing reports
    timing_reports = []
    for root, dirs, files in os.walk(audio_base_dir):
        for file in files:
            if '_timing_' in file and file.endswith('.json'):
                timing_reports.append(os.path.join(root, file))

    # Find all validation reports
    validation_reports = []
    for file in os.listdir(reports_dir):
        if '_validation_' in file and file.endswith('.json'):
            validation_reports.append(os.path.join(reports_dir, file))

    # Aggregate data
    dashboard = {
        'generated_at': datetime.now().isoformat(),
        'overview': {
            'total_videos': len(timing_reports),
            'total_duration_seconds': 0,
            'total_scenes': 0,
            'total_audio_files': 0
        },
        'health': {
            'videos_with_errors': [],
            'videos_with_warnings': [],
            'videos_ready': []
        },
        'videos': []
    }

    # Process each video
    for timing_file in sorted(timing_reports):
        with open(timing_file, 'r') as f:
            timing = json.load(f)

        video_id = timing['video_id']

        # Find matching validation report
        validation = None
        for val_file in validation_reports:
            if video_id in val_file:
                with open(val_file, 'r') as f:
                    validation = json.load(f)
                break

        # Calculate stats
        duration = timing['total_duration']
        scene_count = timing['total_scenes']

        dashboard['overview']['total_duration_seconds'] += duration
        dashboard['overview']['total_scenes'] += scene_count
        dashboard['overview']['total_audio_files'] += scene_count

        # Health status
        has_errors = validation and len(validation.get('issues', [])) > 0
        has_warnings = validation and len(validation.get('warnings', [])) > 0

        if has_errors:
            dashboard['health']['videos_with_errors'].append(video_id)
        elif has_warnings and len(validation['warnings']) > 2:
            dashboard['health']['videos_with_warnings'].append(video_id)
        else:
            dashboard['health']['videos_ready'].append(video_id)

        # Video summary
        video_summary = {
            'video_id': video_id,
            'title': timing.get('title', video_id),
            'duration': duration,
            'scenes': scene_count,
            'status': 'error' if has_errors else ('warning' if has_warnings else 'ready'),
            'issues': validation.get('issues', []) if validation else [],
            'warning_count': len(validation.get('warnings', [])) if validation else 0
        }

        dashboard['videos'].append(video_summary)

    # Summary stats
    total_minutes = dashboard['overview']['total_duration_seconds'] / 60
    dashboard['overview']['total_duration_minutes'] = round(total_minutes, 1)

    # Save dashboard
    dashboard_file = os.path.join(reports_dir, f"aggregate_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(dashboard_file, 'w') as f:
        json.dump(dashboard, f, indent=2)

    # Generate human-readable summary
    summary_file = os.path.join(reports_dir, f"aggregate_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    with open(summary_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AGGREGATE VIDEO DASHBOARD\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Overview
        f.write("OVERVIEW\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Videos:    {dashboard['overview']['total_videos']}\n")
        f.write(f"Total Duration:  {dashboard['overview']['total_duration_minutes']:.1f} minutes\n")
        f.write(f"Total Scenes:    {dashboard['overview']['total_scenes']}\n")
        f.write(f"Audio Files:     {dashboard['overview']['total_audio_files']}\n\n")

        # Health Status
        f.write("HEALTH STATUS\n")
        f.write("-" * 80 + "\n")
        f.write(f"✅ Ready:        {len(dashboard['health']['videos_ready'])} videos\n")
        f.write(f"⚠️  Warnings:     {len(dashboard['health']['videos_with_warnings'])} videos\n")
        f.write(f"❌ Errors:       {len(dashboard['health']['videos_with_errors'])} videos\n\n")

        # Videos with Issues (need attention)
        if dashboard['health']['videos_with_errors']:
            f.write("VIDEOS WITH ERRORS (NEED ATTENTION)\n")
            f.write("-" * 80 + "\n")
            for vid in dashboard['videos']:
                if vid['status'] == 'error':
                    f.write(f"\n❌ {vid['video_id']}\n")
                    f.write(f"   Duration: {vid['duration']:.1f}s | Scenes: {vid['scenes']}\n")
                    for issue in vid['issues']:
                        f.write(f"   ERROR: {issue}\n")

        if dashboard['health']['videos_with_warnings']:
            f.write("\nVIDEOS WITH WARNINGS (REVIEW RECOMMENDED)\n")
            f.write("-" * 80 + "\n")
            for vid in dashboard['videos']:
                if vid['status'] == 'warning':
                    f.write(f"\n⚠️  {vid['video_id']}\n")
                    f.write(f"   Duration: {vid['duration']:.1f}s | Scenes: {vid['scenes']}\n")
                    f.write(f"   Warning count: {vid['warning_count']}\n")

        # All videos summary
        f.write("\n\nALL VIDEOS SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Video ID':<30} {'Duration':<12} {'Scenes':<8} {'Status':<10}\n")
        f.write("-" * 80 + "\n")

        for vid in sorted(dashboard['videos'], key=lambda x: x['video_id']):
            status_icon = {
                'ready': '✅',
                'warning': '⚠️',
                'error': '❌'
            }.get(vid['status'], '?')

            f.write(f"{vid['video_id']:<30} {vid['duration']:>6.1f}s     {vid['scenes']:<8} {status_icon} {vid['status']}\n")

        f.write("\n" + "=" * 80 + "\n")

        # Action items
        f.write("\nACTION ITEMS\n")
        f.write("-" * 80 + "\n")

        if dashboard['health']['videos_with_errors']:
            f.write(f"1. Fix {len(dashboard['health']['videos_with_errors'])} videos with errors (see above)\n")

        if dashboard['health']['videos_with_warnings']:
            f.write(f"2. Review {len(dashboard['health']['videos_with_warnings'])} videos with warnings\n")

        if len(dashboard['health']['videos_ready']) == dashboard['overview']['total_videos']:
            f.write("✅ ALL VIDEOS READY FOR GENERATION!\n")

        f.write("\nNext step: python generate_videos_from_timings_v3_simple.py\n")
        f.write("=" * 80 + "\n")

    print(f"\n{'='*80}")
    print("AGGREGATE DASHBOARD GENERATED")
    print(f"{'='*80}\n")
    print(f"Videos analyzed: {dashboard['overview']['total_videos']}")
    print(f"Total duration:  {dashboard['overview']['total_duration_minutes']:.1f} minutes\n")

    print("📊 Dashboard saved:")
    print(f"   JSON: {os.path.basename(dashboard_file)}")
    print(f"   TXT:  {os.path.basename(summary_file)}\n")

    # Print quick status
    if dashboard['health']['videos_with_errors']:
        print(f"❌ {len(dashboard['health']['videos_with_errors'])} videos have errors - FIX REQUIRED")
        for vid_id in dashboard['health']['videos_with_errors']:
            print(f"   - {vid_id}")

    if dashboard['health']['videos_with_warnings']:
        print(f"\n⚠️  {len(dashboard['health']['videos_with_warnings'])} videos have warnings - REVIEW RECOMMENDED")
        for vid_id in dashboard['health']['videos_with_warnings']:
            print(f"   - {vid_id}")

    if len(dashboard['health']['videos_ready']) == dashboard['overview']['total_videos']:
        print("✅ ALL VIDEOS READY FOR GENERATION!")
    else:
        print(f"\n✅ {len(dashboard['health']['videos_ready'])} videos ready")

    print(f"\n{'='*80}\n")

    return dashboard, summary_file

if __name__ == "__main__":
    audio_dir = "../audio/unified_system_v2"

    if not os.path.exists(audio_dir):
        print(f"❌ Audio directory not found: {audio_dir}")
        print("Run generate_all_videos_unified_v2.py first!")
        exit(1)

    dashboard, summary = generate_aggregate_dashboard(audio_dir)

    print(f"📄 Read the summary:\n   cat {summary}")
