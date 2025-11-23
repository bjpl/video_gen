/**
 * Alpine.js Global State Store - Enhanced
 *
 * Features:
 * - Comprehensive state management for all components
 * - State persistence with localStorage
 * - State validation and migration
 * - Event bus integration
 * - Reset and cleanup utilities
 */

// State version for migrations
const STATE_VERSION = '2.0.0';

// Keys to persist to localStorage
const PERSISTED_KEYS = [
    'currentStep',
    'maxStepReached',
    'selectedInputMethod',
    'videoConfig',
    'ui.darkMode',
    'ui.sidebarCollapsed'
];

// Keys that should NOT be persisted (session-only)
const SESSION_KEYS = [
    'formData.document.file',
    'formData.document.content',
    'preview.data',
    'generation.progress',
    'generation.stages',
    'validation.errors',
    'ui.notifications'
];

document.addEventListener('alpine:init', () => {
    Alpine.store('appState', {
        // ==================== STATE VERSION ====================
        _version: STATE_VERSION,
        _initialized: false,

        // ==================== WIZARD STATE ====================
        currentStep: 1,
        maxStepReached: 1,

        // ==================== INPUT STATE ====================
        input: {
            type: 'document', // 'document' | 'youtube' | 'wizard' | 'yaml'
            source: null,     // Raw source (URL, file ref, etc.)
            file: null,       // File object (for uploads)
            content: null,    // Parsed content
            isValid: false,
            validationErrors: [],
            validationWarnings: []
        },

        // Legacy: selectedInputMethod for backward compatibility
        selectedInputMethod: null,

        // Legacy: formData for backward compatibility
        formData: {
            document: {
                file: null,
                fileName: '',
                uploadProgress: 0,
                content: null
            },
            youtube: {
                url: '',
                validated: false,
                videoInfo: null
            },
            wizard: {
                currentQuestion: 0,
                totalQuestions: 5,
                answers: [],
                completed: false
            },
            yaml: {
                content: '',
                parsed: null,
                valid: false
            }
        },

        // ==================== PREVIEW STATE ====================
        preview: {
            data: null,
            type: null,           // 'document' | 'youtube' | 'yaml'
            isLoading: false,
            error: null,
            sections: [],
            estimatedScenes: 0,
            estimatedDuration: 0
        },

        // ==================== VIDEO CONFIGURATION ====================
        videoConfig: {
            // Basic
            videoId: '',
            title: '',

            // Mode
            mode: 'single',       // 'single' | 'set'
            videoCount: 1,

            // Languages
            languageMode: 'single',
            targetLanguages: ['en'],

            // Voices per language
            languageVoices: {
                'en': ['en-US-JennyNeural']
            },

            // Styling
            aspectRatio: '16:9',
            accentColor: 'blue',

            // Duration
            duration: 120,

            // AI Narration (always enabled)
            useAiNarration: true,
            narration: {
                enabled: true,
                style: 'professional',
                speed: 1.0
            },

            // Slides/scenes
            slides: [],

            // Custom settings
            customizations: {},

            // Preset
            selectedPreset: null
        },

        // ==================== LANGUAGES STATE ====================
        languages: {
            available: [],        // All available languages
            selected: ['en'],     // Selected language codes
            isLoading: false,
            error: null,
            lastFetched: null
        },

        // ==================== VOICES STATE ====================
        voices: {
            byLanguage: {},       // { 'en': [{id, name, gender, ...}] }
            selected: {           // { 'en': ['voice-id-1', 'voice-id-2'] }
                'en': []
            },
            isLoading: {},        // { 'en': false }
            error: null,
            previewing: null      // Currently previewing voice ID
        },

        // ==================== PROGRESS STATE ====================
        progress: {
            isProcessing: false,
            taskId: null,
            currentStage: null,
            progress: 0,
            stages: [
                { id: 'parsing', label: 'Parsing Content', status: 'pending', progress: 0 },
                { id: 'generating', label: 'Generating Scenes', status: 'pending', progress: 0 },
                { id: 'rendering', label: 'Rendering Video', status: 'pending', progress: 0 },
                { id: 'complete', label: 'Complete', status: 'pending', progress: 0 }
            ],
            timeElapsed: 0,
            timeRemaining: null,
            startTime: null,
            error: null,
            result: null
        },

        // Legacy: generation for backward compatibility
        generation: {
            inProgress: false,
            currentStage: null,
            progress: 0,
            stages: [
                { id: 'parsing', label: 'Parsing Content', status: 'pending' },
                { id: 'generating', label: 'Generating Scenes', status: 'pending' },
                { id: 'rendering', label: 'Rendering Video', status: 'pending' },
                { id: 'complete', label: 'Complete', status: 'pending' }
            ],
            videoUrl: null,
            error: null
        },

        // ==================== VALIDATION STATE ====================
        validation: {
            errors: [],
            warnings: [],
            isValid: false,
            lastValidated: null
        },

        // ==================== UI STATE ====================
        ui: {
            activeSection: 'input',
            showPreview: false,
            showProgress: false,
            sidebarCollapsed: false,
            darkMode: false,
            toasts: [],
            notifications: [],
            modals: {
                voicePreview: false,
                presetSelector: false,
                confirmReset: false
            },
            loading: {
                languages: false,
                voices: false,
                preview: false,
                validation: false
            }
        },

        // ==================== INITIALIZATION ====================

        init() {
            if (this._initialized) return;

            // Load persisted state
            this.loadFromStorage();

            // Setup watchers for auto-save
            this._setupWatchers();

            // Setup event bus listeners
            this._setupEventListeners();

            this._initialized = true;
            console.log('[AppState] Initialized', this.getSummary());

            // Emit initialization event
            if (window.eventBus) {
                window.eventBus.emit('state:initialized', this.getSummary());
            }
        },

        // ==================== WATCHER SETUP ====================

        _setupWatchers() {
            // Auto-save on key changes
            const watchKeys = [
                'currentStep',
                'selectedInputMethod',
                'videoConfig',
                'ui.darkMode',
                'ui.sidebarCollapsed'
            ];

            // Note: Alpine's $watch is available within Alpine context
            // This is called from init() which runs in Alpine context
        },

        // ==================== EVENT LISTENERS ====================

        _setupEventListeners() {
            if (!window.eventBus) return;

            // Listen for validation events
            window.eventBus.on('validation:success', (data) => {
                this.input.isValid = true;
                this.input.validationErrors = [];
            });

            window.eventBus.on('validation:error', (data) => {
                this.input.isValid = false;
                this.input.validationErrors = data.errors || [];
            });

            // Listen for progress events
            window.eventBus.on('progress:updated', (data) => {
                this.updateProgress(data);
            });
        },

        // ==================== PERSISTENCE METHODS ====================

        saveToStorage() {
            if (!window.storage) {
                // Fallback to direct localStorage
                try {
                    const state = this._getPersistedState();
                    localStorage.setItem('appState', JSON.stringify({
                        ...state,
                        _version: STATE_VERSION,
                        _savedAt: Date.now()
                    }));
                    console.log('[AppState] Saved to localStorage');
                } catch (error) {
                    console.error('[AppState] Failed to save:', error);
                }
                return;
            }

            window.storage.set('state', {
                ...this._getPersistedState(),
                _version: STATE_VERSION,
                _savedAt: Date.now()
            });
            console.log('[AppState] Saved to storage');

            if (window.eventBus) {
                window.eventBus.emit('storage:saved', { version: STATE_VERSION });
            }
        },

        loadFromStorage() {
            let saved = null;

            if (window.storage) {
                saved = window.storage.get('state');
            } else {
                // Fallback to direct localStorage
                try {
                    const raw = localStorage.getItem('appState');
                    if (raw) saved = JSON.parse(raw);
                } catch (error) {
                    console.error('[AppState] Failed to load:', error);
                }
            }

            if (saved) {
                // Check version and migrate if needed
                if (saved._version !== STATE_VERSION) {
                    console.log(`[AppState] Migrating from ${saved._version} to ${STATE_VERSION}`);
                    saved = this._migrateState(saved);
                }

                // Apply saved state
                this._applyPersistedState(saved);
                console.log('[AppState] Loaded from storage');

                if (window.eventBus) {
                    window.eventBus.emit('storage:loaded', { version: STATE_VERSION });
                }
            }
        },

        clearStorage() {
            if (window.storage) {
                window.storage.remove('state');
            } else {
                localStorage.removeItem('appState');
            }
            console.log('[AppState] Storage cleared');

            if (window.eventBus) {
                window.eventBus.emit('storage:cleared');
            }
        },

        _getPersistedState() {
            return {
                currentStep: this.currentStep,
                maxStepReached: this.maxStepReached,
                selectedInputMethod: this.selectedInputMethod,
                videoConfig: this.videoConfig,
                languages: {
                    selected: this.languages.selected
                },
                voices: {
                    selected: this.voices.selected
                },
                ui: {
                    darkMode: this.ui.darkMode,
                    sidebarCollapsed: this.ui.sidebarCollapsed
                }
            };
        },

        _applyPersistedState(saved) {
            // Apply saved values safely
            if (saved.currentStep) this.currentStep = saved.currentStep;
            if (saved.maxStepReached) this.maxStepReached = saved.maxStepReached;
            if (saved.selectedInputMethod) this.selectedInputMethod = saved.selectedInputMethod;

            if (saved.videoConfig) {
                Object.assign(this.videoConfig, saved.videoConfig);
            }

            if (saved.languages?.selected) {
                this.languages.selected = saved.languages.selected;
            }

            if (saved.voices?.selected) {
                this.voices.selected = saved.voices.selected;
            }

            if (saved.ui) {
                if (typeof saved.ui.darkMode === 'boolean') {
                    this.ui.darkMode = saved.ui.darkMode;
                }
                if (typeof saved.ui.sidebarCollapsed === 'boolean') {
                    this.ui.sidebarCollapsed = saved.ui.sidebarCollapsed;
                }
            }
        },

        _migrateState(oldState) {
            // Add migration logic here
            // Example: migrate from 1.x to 2.x

            const migrated = { ...oldState };
            migrated._version = STATE_VERSION;

            return migrated;
        },

        // ==================== STATE VALIDATION ====================

        validateState() {
            const errors = [];

            // Validate input
            if (this.currentStep > 1 && !this.selectedInputMethod) {
                errors.push('Input method not selected');
            }

            // Validate languages
            if (this.languages.selected.length === 0) {
                errors.push('At least one language must be selected');
            }

            // Validate video config
            if (this.videoConfig.duration < 10 || this.videoConfig.duration > 600) {
                errors.push('Duration must be between 10 and 600 seconds');
            }

            this.validation.errors = errors;
            this.validation.isValid = errors.length === 0;
            this.validation.lastValidated = Date.now();

            return this.validation.isValid;
        },

        // ==================== STEP NAVIGATION ====================

        goToStep(step) {
            if (step < 1 || step > 4) {
                console.warn('[AppState] Invalid step:', step);
                return false;
            }

            if (step > this.currentStep && !this.canAdvanceToStep(step)) {
                console.warn('[AppState] Cannot advance to step:', step);
                return false;
            }

            this.currentStep = step;
            this.maxStepReached = Math.max(this.maxStepReached, step);
            this.saveToStorage();

            console.log('[AppState] Moved to step:', step);

            if (window.eventBus) {
                window.eventBus.emit('ui:step-changed', { step, maxReached: this.maxStepReached });
            }

            return true;
        },

        nextStep() {
            return this.goToStep(this.currentStep + 1);
        },

        previousStep() {
            return this.goToStep(this.currentStep - 1);
        },

        canAdvanceToStep(step) {
            switch (step) {
                case 2:
                    return this.selectedInputMethod !== null || this.input.type !== null;
                case 3:
                    return this.isInputMethodComplete();
                case 4:
                    return this.validation.isValid;
                default:
                    return true;
            }
        },

        // ==================== INPUT MANAGEMENT ====================

        selectInputMethod(method) {
            const validMethods = ['document', 'youtube', 'wizard', 'yaml'];
            if (!validMethods.includes(method)) {
                console.warn('[AppState] Invalid input method:', method);
                return false;
            }

            this.selectedInputMethod = method;
            this.input.type = method;
            this.saveToStorage();

            console.log('[AppState] Input method selected:', method);

            if (window.eventBus) {
                window.eventBus.emit('input:method-changed', { method });
            }

            return true;
        },

        setInputFile(file, content = null) {
            this.formData.document.file = file;
            this.formData.document.fileName = file?.name || '';
            this.formData.document.content = content;

            this.input.file = file;
            this.input.content = content;

            console.log('[AppState] File set:', file?.name);
        },

        setInputURL(url) {
            this.formData.youtube.url = url;
            this.input.source = url;

            console.log('[AppState] URL set:', url);
        },

        clearInput() {
            this.input = {
                type: this.input.type,
                source: null,
                file: null,
                content: null,
                isValid: false,
                validationErrors: [],
                validationWarnings: []
            };

            this.formData.document = { file: null, fileName: '', uploadProgress: 0, content: null };
            this.formData.youtube = { url: '', validated: false, videoInfo: null };
            this.formData.yaml = { content: '', parsed: null, valid: false };

            this.preview.data = null;
            this.preview.sections = [];

            if (window.eventBus) {
                window.eventBus.emit('input:cleared');
            }
        },

        isInputMethodComplete() {
            if (!this.selectedInputMethod) return false;

            switch (this.selectedInputMethod) {
                case 'document':
                    return !!this.formData.document.file || !!this.input.file;
                case 'youtube':
                    return this.formData.youtube.validated || !!this.input.source;
                case 'wizard':
                    return this.formData.wizard.completed;
                case 'yaml':
                    return this.formData.yaml.valid;
                default:
                    return false;
            }
        },

        // ==================== PREVIEW MANAGEMENT ====================

        setPreview(data, type) {
            this.preview.data = data;
            this.preview.type = type;
            this.preview.isLoading = false;
            this.preview.error = null;

            if (data?.sections) {
                this.preview.sections = data.sections;
            }
            if (data?.estimated_scenes) {
                this.preview.estimatedScenes = data.estimated_scenes;
            }
            if (data?.estimated_duration) {
                this.preview.estimatedDuration = data.estimated_duration;
            }

            if (window.eventBus) {
                window.eventBus.emit('preview:loaded', { type, data });
            }
        },

        setPreviewLoading(loading) {
            this.preview.isLoading = loading;
            if (loading && window.eventBus) {
                window.eventBus.emit('preview:loading');
            }
        },

        setPreviewError(error) {
            this.preview.error = error;
            this.preview.isLoading = false;

            if (window.eventBus) {
                window.eventBus.emit('preview:error', { error });
            }
        },

        clearPreview() {
            this.preview = {
                data: null,
                type: null,
                isLoading: false,
                error: null,
                sections: [],
                estimatedScenes: 0,
                estimatedDuration: 0
            };

            if (window.eventBus) {
                window.eventBus.emit('preview:cleared');
            }
        },

        // ==================== LANGUAGE MANAGEMENT ====================

        setAvailableLanguages(languages) {
            this.languages.available = languages;
            this.languages.lastFetched = Date.now();
            this.languages.isLoading = false;

            if (window.eventBus) {
                window.eventBus.emit('languages:loaded', { languages });
            }
        },

        selectLanguage(langCode) {
            if (!this.languages.selected.includes(langCode)) {
                this.languages.selected.push(langCode);
                this.videoConfig.targetLanguages = [...this.languages.selected];

                // Initialize voice selection for new language
                if (!this.voices.selected[langCode]) {
                    this.voices.selected[langCode] = [];
                }

                this.saveToStorage();

                if (window.eventBus) {
                    window.eventBus.emit('language:selected', { langCode });
                }
            }
        },

        deselectLanguage(langCode) {
            const index = this.languages.selected.indexOf(langCode);
            if (index > -1) {
                this.languages.selected.splice(index, 1);
                this.videoConfig.targetLanguages = [...this.languages.selected];

                // Remove voice selection for this language
                delete this.voices.selected[langCode];

                this.saveToStorage();

                if (window.eventBus) {
                    window.eventBus.emit('language:deselected', { langCode });
                }
            }
        },

        toggleLanguage(langCode) {
            if (this.languages.selected.includes(langCode)) {
                // Don't allow deselecting the last language
                if (this.languages.selected.length > 1) {
                    this.deselectLanguage(langCode);
                }
            } else {
                this.selectLanguage(langCode);
            }
        },

        // ==================== VOICE MANAGEMENT ====================

        setVoicesForLanguage(langCode, voices) {
            this.voices.byLanguage[langCode] = voices;
            this.voices.isLoading[langCode] = false;

            if (window.eventBus) {
                window.eventBus.emit('voices:loaded', { langCode, voices });
            }
        },

        selectVoice(langCode, voiceId) {
            if (!this.voices.selected[langCode]) {
                this.voices.selected[langCode] = [];
            }

            if (!this.voices.selected[langCode].includes(voiceId)) {
                this.voices.selected[langCode].push(voiceId);
                this.videoConfig.languageVoices[langCode] = [...this.voices.selected[langCode]];
                this.saveToStorage();

                if (window.eventBus) {
                    window.eventBus.emit('voice:selected', { langCode, voiceId });
                }
            }
        },

        deselectVoice(langCode, voiceId) {
            if (this.voices.selected[langCode]) {
                const index = this.voices.selected[langCode].indexOf(voiceId);
                if (index > -1) {
                    this.voices.selected[langCode].splice(index, 1);
                    this.videoConfig.languageVoices[langCode] = [...this.voices.selected[langCode]];
                    this.saveToStorage();

                    if (window.eventBus) {
                        window.eventBus.emit('voice:deselected', { langCode, voiceId });
                    }
                }
            }
        },

        toggleVoice(langCode, voiceId) {
            if (this.voices.selected[langCode]?.includes(voiceId)) {
                // Don't allow deselecting the last voice for a language
                if (this.voices.selected[langCode].length > 1) {
                    this.deselectVoice(langCode, voiceId);
                }
            } else {
                this.selectVoice(langCode, voiceId);
            }
        },

        // ==================== PROGRESS MANAGEMENT ====================

        startProgress(taskId) {
            this.progress.isProcessing = true;
            this.progress.taskId = taskId;
            this.progress.currentStage = 'parsing';
            this.progress.progress = 0;
            this.progress.startTime = Date.now();
            this.progress.timeElapsed = 0;
            this.progress.timeRemaining = null;
            this.progress.error = null;
            this.progress.result = null;

            // Reset stages
            this.progress.stages.forEach(stage => {
                stage.status = 'pending';
                stage.progress = 0;
            });
            this.progress.stages[0].status = 'active';

            // Legacy
            this.generation.inProgress = true;
            this.generation.currentStage = 'parsing';
            this.generation.error = null;

            console.log('[AppState] Progress started:', taskId);

            if (window.eventBus) {
                window.eventBus.emit('progress:started', { taskId });
            }
        },

        updateProgress(data) {
            if (data.progress !== undefined) {
                this.progress.progress = data.progress;
                this.generation.progress = data.progress;
            }

            if (data.stage) {
                this.progress.currentStage = data.stage;
                this.generation.currentStage = data.stage;
                this._updateStageStatus(data.stage, 'active');
            }

            if (this.progress.startTime) {
                this.progress.timeElapsed = Date.now() - this.progress.startTime;
            }

            if (data.timeRemaining !== undefined) {
                this.progress.timeRemaining = data.timeRemaining;
            }

            console.log(`[AppState] Progress: ${data.stage || ''} - ${data.progress || 0}%`);

            if (window.eventBus) {
                window.eventBus.emit('progress:updated', data);
            }
        },

        completeProgress(result) {
            this.progress.isProcessing = false;
            this.progress.progress = 100;
            this.progress.currentStage = 'complete';
            this.progress.result = result;

            // Mark all stages complete
            this.progress.stages.forEach(stage => {
                stage.status = 'complete';
                stage.progress = 100;
            });

            // Legacy
            this.generation.inProgress = false;
            this.generation.progress = 100;
            this.generation.currentStage = 'complete';
            this.generation.videoUrl = result?.videoUrl || result?.url;

            console.log('[AppState] Progress complete:', result);

            if (window.eventBus) {
                window.eventBus.emit('progress:completed', { result });
            }
        },

        failProgress(error) {
            this.progress.isProcessing = false;
            this.progress.error = error;

            if (this.progress.currentStage) {
                this._updateStageStatus(this.progress.currentStage, 'error');
            }

            // Legacy
            this.generation.inProgress = false;
            this.generation.error = error;

            console.error('[AppState] Progress failed:', error);

            if (window.eventBus) {
                window.eventBus.emit('progress:failed', { error });
            }
        },

        cancelProgress() {
            this.progress.isProcessing = false;
            this.progress.error = 'Cancelled by user';

            // Legacy
            this.generation.inProgress = false;

            console.log('[AppState] Progress cancelled');

            if (window.eventBus) {
                window.eventBus.emit('progress:cancelled', { taskId: this.progress.taskId });
            }
        },

        _updateStageStatus(stageId, status) {
            const stage = this.progress.stages.find(s => s.id === stageId);
            if (stage) {
                stage.status = status;
            }

            // Also update legacy generation stages
            const legacyStage = this.generation.stages.find(s => s.id === stageId);
            if (legacyStage) {
                legacyStage.status = status;
            }
        },

        // ==================== VIDEO GENERATION (Legacy) ====================

        startGeneration() {
            this.startProgress(null);
        },

        updateGenerationProgress(stage, progress) {
            this.updateProgress({ stage, progress });
        },

        completeGeneration(videoUrl) {
            this.completeProgress({ videoUrl });
        },

        failGeneration(error) {
            this.failProgress(error);
        },

        updateStageStatus(stageId, status) {
            this._updateStageStatus(stageId, status);
        },

        // ==================== VALIDATION (Legacy) ====================

        validate() {
            return this.validateState();
        },

        // ==================== NOTIFICATIONS ====================

        addNotification(type, message, duration = 5000) {
            const notification = {
                id: Date.now(),
                type,
                message,
                timestamp: new Date()
            };
            this.ui.notifications.push(notification);
            this.ui.toasts.push(notification);

            if (duration > 0) {
                setTimeout(() => {
                    this.removeNotification(notification.id);
                }, duration);
            }

            return notification.id;
        },

        removeNotification(id) {
            this.ui.notifications = this.ui.notifications.filter(n => n.id !== id);
            this.ui.toasts = this.ui.toasts.filter(t => t.id !== id);
        },

        clearNotifications() {
            this.ui.notifications = [];
            this.ui.toasts = [];
        },

        // ==================== UTILITIES ====================

        reset() {
            // Reset all state to defaults
            this.currentStep = 1;
            this.maxStepReached = 1;
            this.selectedInputMethod = null;

            this.input = {
                type: 'document',
                source: null,
                file: null,
                content: null,
                isValid: false,
                validationErrors: [],
                validationWarnings: []
            };

            this.formData = {
                document: { file: null, fileName: '', uploadProgress: 0, content: null },
                youtube: { url: '', validated: false, videoInfo: null },
                wizard: { currentQuestion: 0, totalQuestions: 5, answers: [], completed: false },
                yaml: { content: '', parsed: null, valid: false }
            };

            this.preview = {
                data: null,
                type: null,
                isLoading: false,
                error: null,
                sections: [],
                estimatedScenes: 0,
                estimatedDuration: 0
            };

            this.videoConfig = {
                videoId: '',
                title: '',
                mode: 'single',
                videoCount: 1,
                languageMode: 'single',
                targetLanguages: ['en'],
                languageVoices: { 'en': ['en-US-JennyNeural'] },
                aspectRatio: '16:9',
                accentColor: 'blue',
                duration: 120,
                useAiNarration: true,
                narration: { enabled: true, style: 'professional', speed: 1.0 },
                slides: [],
                customizations: {},
                selectedPreset: null
            };

            this.languages.selected = ['en'];
            this.voices.selected = { 'en': [] };

            this.progress = {
                isProcessing: false,
                taskId: null,
                currentStage: null,
                progress: 0,
                stages: [
                    { id: 'parsing', label: 'Parsing Content', status: 'pending', progress: 0 },
                    { id: 'generating', label: 'Generating Scenes', status: 'pending', progress: 0 },
                    { id: 'rendering', label: 'Rendering Video', status: 'pending', progress: 0 },
                    { id: 'complete', label: 'Complete', status: 'pending', progress: 0 }
                ],
                timeElapsed: 0,
                timeRemaining: null,
                startTime: null,
                error: null,
                result: null
            };

            this.generation = {
                inProgress: false,
                currentStage: null,
                progress: 0,
                stages: [
                    { id: 'parsing', label: 'Parsing Content', status: 'pending' },
                    { id: 'generating', label: 'Generating Scenes', status: 'pending' },
                    { id: 'rendering', label: 'Rendering Video', status: 'pending' },
                    { id: 'complete', label: 'Complete', status: 'pending' }
                ],
                videoUrl: null,
                error: null
            };

            this.validation = { errors: [], warnings: [], isValid: false, lastValidated: null };

            this.clearStorage();
            console.log('[AppState] Reset complete');

            if (window.eventBus) {
                window.eventBus.emit('config:reset');
            }
        },

        getSummary() {
            return {
                version: this._version,
                step: this.currentStep,
                inputMethod: this.selectedInputMethod,
                inputComplete: this.isInputMethodComplete(),
                valid: this.validation.isValid,
                generating: this.progress.isProcessing || this.generation.inProgress,
                languages: this.languages.selected,
                progress: this.progress.progress
            };
        },

        // Export state for debugging
        exportState() {
            return JSON.stringify({
                version: this._version,
                currentStep: this.currentStep,
                selectedInputMethod: this.selectedInputMethod,
                videoConfig: this.videoConfig,
                languages: this.languages,
                voices: this.voices,
                progress: this.progress,
                validation: this.validation
            }, null, 2);
        }
    });
});
