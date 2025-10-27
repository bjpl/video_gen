# Three Input Methods - Narration Script

**Video ID:** 02_input_methods
**Version:** v2.0
**Accent Color:** blue
**Default Voice:** female

**Estimated Total Duration:** 224.0s (3.7 minutes)
**Total Words:** 504
**Average Pace:** 135 WPM

---

## Scene 1: scene_01 (TITLE)

**Duration:** 3.0s - 15.0s (estimated: 8.4s)
**Voice:** female

**Narration:**
> "The system accepts content through three distinct input methods. Select documents, YouTube URLs, or use the guided wizard interface."

**Word Count:** 19 words
**Pacing:** 136 WPM

**Visual Content:**
- title: Three Input Methods
- subtitle: Choose Your Content Source

---

## Scene 2: scene_02 (COMMAND)

**Duration:** 3.0s - 15.0s (estimated: 48.4s)
**Voice:** male

**Narration:**
> "The document parser extracts content from existing documentation and converts it into video format. This method works directly with GitHub repositories and local markdown files.

First, we'll initialize the parser with your documentation source. The system reads through your existing docs and identifies the structure.

Next, we'll configure the output settings for video generation. This determines resolution, format, and visual styling for your documentation videos.

Now we'll run the parsing command to process your documentation. The parser extracts headings, code blocks, and explanatory text automatically.

Finally, we'll generate the video files from the parsed content. Each documentation section becomes a separate video segment with synchronized narration and code display."

**Word Count:** 109 words
**Pacing:** 135 WPM

**Visual Content:**
- header: Method 1: Document Parser
- description: From README to Video in 30 Seconds
- commands:
  - $ python create_video.py --document README.md
  - # Parses structure automatically
  - # Extracts headings, code, lists
  - # Generates YAML and narration
  - → Ready to generate in 30 seconds

---

## Scene 3: scene_03 (COMMAND)

**Duration:** 3.0s - 15.0s (estimated: 52.9s)
**Voice:** female

**Narration:**
> "Method 2 uses YouTube's built-in transcription to extract key information from video content. This approach works well when you need to reference existing tutorials or documentation videos.

First, we'll access the video's transcript data using the YouTube API. This command retrieves the automatically generated captions along with timestamp information.

Next, we parse the transcript text to remove formatting and combine fragmented sentences. The parser handles common transcription errors and creates readable text blocks.

We then apply text analysis to identify the main topics and technical concepts. This command scans for keywords, code references, and procedural steps within the transcript.

The fourth command segments the content by topics or time intervals. This creates logical sections that correspond to different concepts"

**Word Count:** 119 words
**Pacing:** 135 WPM

**Visual Content:**
- header: Method 2: YouTube Transcription
- description: Condense Long Tutorials to Summaries
- commands:
  - $ python create_video.py --youtube-url 'VIDEO_URL'
  - # Fetches video transcript
  - # Analyzes segments
  - # Extracts key points
  - → 60-second summary from 15-minute video

---

## Scene 4: scene_04 (COMMAND)

**Duration:** 3.0s - 15.0s (estimated: 50.7s)
**Voice:** male_warm

**Narration:**
> "The interactive wizard walks you through video creation using structured prompts and questions. This method suits beginners who need guidance while maintaining full control over their content.

Start the wizard to begin the question-and-answer interface. The system prompts for video specifications, content preferences, and technical requirements through sequential dialogs.

Configure your project settings when prompted. Answer questions about duration, resolution, format, and target audience to establish the foundation parameters.

Define content elements through guided prompts. Specify text overlays, image sequences, audio tracks, and transition styles using the structured input system.

Review and generate your video after completing all wizard steps. The system compiles your responses into executable commands and processes the final output file."

**Word Count:** 114 words
**Pacing:** 135 WPM

**Visual Content:**
- header: Method 3: Interactive Wizard
- description: Guided Step-by-Step Creation
- commands:
  - $ python create_video.py --wizard
  - # What's your video about?
  - # What topics to cover?
  - # What commands to show?
  - → Professional script generated from your answers

---

## Scene 5: scene_05 (LIST)

**Duration:** 3.0s - 15.0s (estimated: 55.6s)
**Voice:** female_friendly

**Narration:**
> "The input method you select determines the processing workflow and required steps for content creation. Each method offers different advantages based on your available source materials.

Have Documentation? This method processes existing written materials such as user manuals, specifications, or technical guides. The system extracts key information from structured documents and converts them into the target format. This approach works best when you have comprehensive source documentation that covers the required topics.

Found YouTube Video? This method extracts content from video sources through automated transcription and analysis. The system processes the audio track, generates text transcripts, and identifies key concepts and explanations. This option is suitable when video content contains the information you need but lacks accompanying written materials.

Starting from Scratch? This method creates"

**Word Count:** 125 words
**Pacing:** 135 WPM

**Visual Content:**
- header: Choose the Right Method
- description: Decision Guide
- items:
  - ('Have Documentation?', 'Use document parser (fastest)')
  - ('Found YouTube Video?', 'Use transcription fetcher')
  - ('Starting from Scratch?', 'Use interactive wizard')

---

## Scene 6: scene_06 (OUTRO)

**Duration:** 3.0s - 15.0s (estimated: 8.0s)
**Voice:** female

**Narration:**
> "Three input methods deliver the same output format. Reference THREE_INPUT_METHODS_GUIDE.md for implementation details specific to your content source."

**Word Count:** 18 words
**Pacing:** 135 WPM

**Visual Content:**
- main_text: Three Paths, One Result
- sub_text: THREE_INPUT_METHODS_GUIDE.md

---


*Generated: 2025-10-04 02:33:10*
*Edit this script, then regenerate code with: python import_script.py*
