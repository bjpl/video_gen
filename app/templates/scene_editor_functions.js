// SCENE EDITOR JAVASCRIPT FUNCTIONS
// Add these functions to the videoCreator() Alpine.js component

// Scene manipulation functions - add after removeVoiceTrack()

addScene(mode, videoIdx, sceneType) {
    const config = mode === 'single' ? this.single : this.set;

    // Initialize scenes array if it doesn't exist
    if (!config.videos[videoIdx].scenes) {
        config.videos[videoIdx].scenes = [];
    }

    // Create scene template based on type
    const sceneTemplates = {
        title: {
            type: 'title',
            title: '',
            subtitle: ''
        },
        command: {
            type: 'command',
            header: '',
            description: '',
            commands: ''
        },
        list: {
            type: 'list',
            header: '',
            description: '',
            items: ''
        },
        outro: {
            type: 'outro',
            message: '',
            cta: ''
        },
        quiz: {
            type: 'quiz',
            question: '',
            options: '',
            answer: ''
        },
        slide: {
            type: 'slide',
            header: '',
            content: ''
        }
    };

    const newScene = sceneTemplates[sceneType] || sceneTemplates.title;
    config.videos[videoIdx].scenes.push(newScene);
},

removeScene(mode, videoIdx, sceneIdx) {
    const config = mode === 'single' ? this.single : this.set;
    if (config.videos[videoIdx].scenes && config.videos[videoIdx].scenes.length > 0) {
        config.videos[videoIdx].scenes.splice(sceneIdx, 1);
    }
},

// Update the updateVideoList function to initialize scenes for new videos
updateVideoList(mode) {
    const config = mode === 'single' ? this.single : this.set;
    const currentCount = config.videos.length;
    const targetCount = config.videoCount;

    if (targetCount > currentCount) {
        // Add videos
        for (let i = currentCount; i < targetCount; i++) {
            config.videos.push({
                title: `Video ${i + 1}`,
                voices: ['male'],
                duration: null,
                scenes: [{ type: 'title', title: '', subtitle: '' }],
                showScenes: false
            });
        }
    } else if (targetCount < currentCount) {
        // Remove videos
        config.videos = config.videos.slice(0, targetCount);
    }
},

// Update initial data structures to include scenes
// In single.videos[0]:
// scenes: [{ type: 'title', title: '', subtitle: '' }]
// showScenes: false

// In set.videos (each video):
// scenes: [{ type: 'title', title: '', subtitle: '' }]
// showScenes: false

// Update generateSingle() to include scenes in payload
async generateSingle() {
    this.loading = true;
    try {
        let endpoint, payload;

        if (this.single.inputMethod === 'manual') {
            const videoData = {
                video_id: 'single_' + Date.now(),
                title: this.single.videos[0].title || this.single.title || 'Single Video',
                voices: this.single.videos[0].voices,
                duration: this.single.videos[0].duration || this.single.duration,
                scenes: this.single.videos[0].scenes || []  // Include scenes
            };

            endpoint = this.single.multilingual ? '/api/generate/multilingual' : '/api/generate';
            payload = this.single.multilingual ? {
                video_set: {
                    set_id: 'single_' + Date.now(),
                    set_name: videoData.title,
                    videos: [videoData],
                    accent_color: this.single.color
                },
                target_languages: this.single.targetLanguages,
                source_language: this.single.sourceLanguage,
                translation_method: this.single.translationMethod
            } : {
                video_set: {
                    set_id: 'single_' + Date.now(),
                    set_name: videoData.title,
                    videos: [videoData],
                    accent_color: this.single.color,
                    languages: [this.single.sourceLanguage]
                }
            };
        }
        // ... rest of function
    }
    // ... rest of function
},

// Update generateSet() to include scenes in payload
async generateSet() {
    this.loading = true;
    try {
        if (this.set.inputMethod === 'manual') {
            const videosData = this.set.videos.map((video, i) => ({
                video_id: `video_${i+1}`,
                title: video.title || `Video ${i+1}`,
                voices: video.voices,
                duration: video.duration || this.set.duration,
                scenes: video.scenes || []  // Include scenes
            }));

            endpoint = this.set.multilingual ? '/api/generate/multilingual' : '/api/generate';
            payload = this.set.multilingual ? {
                video_set: {
                    set_id: 'set_' + Date.now(),
                    set_name: this.set.name || 'Video Set',
                    videos: videosData,
                    accent_color: this.set.color
                },
                target_languages: this.set.targetLanguages,
                source_language: this.set.sourceLanguage,
                translation_method: this.set.translationMethod
            } : {
                video_set: {
                    set_id: 'set_' + Date.now(),
                    set_name: this.set.name || 'Video Set',
                    videos: videosData,
                    accent_color: this.set.color,
                    languages: [this.set.sourceLanguage]
                }
            };
        }
        // ... rest of function
    }
    // ... rest of function
}
