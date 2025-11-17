/**
 * Alpine.js Global State Store
 * Manages application state, persistence, and transitions
 */

document.addEventListener('alpine:init', () => {
  Alpine.store('appState', {
    // ==================== STATE DEFINITION ====================

    // Workflow step tracking (1-4)
    currentStep: 1,
    maxStepReached: 1,

    // Input method selection
    selectedInputMethod: null, // 'document', 'youtube', 'wizard', 'yaml'

    // Form data for each input method
    formData: {
      document: {
        file: null,
        fileName: '',
        uploadProgress: 0
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

    // Video configuration
    videoConfig: {
      title: '',
      aspectRatio: '16:9',
      duration: null,
      language: 'en',
      narration: {
        enabled: true,
        style: 'professional',
        speed: 1.0
      },
      slides: [],
      customizations: {}
    },

    // Generation status
    generation: {
      inProgress: false,
      currentStage: null, // 'parsing', 'generating', 'rendering', 'complete'
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

    // Validation state
    validation: {
      errors: [],
      warnings: [],
      isValid: false
    },

    // UI state
    ui: {
      sidebarCollapsed: false,
      darkMode: false,
      notifications: []
    },

    // ==================== INITIALIZATION ====================

    init() {
      // Load persisted state from localStorage
      this.loadFromStorage();

      // Set up auto-save on state changes
      this.$watch('currentStep', () => this.saveToStorage());
      this.$watch('selectedInputMethod', () => this.saveToStorage());
      this.$watch('formData', () => this.saveToStorage());
      this.$watch('videoConfig', () => this.saveToStorage());

      console.log('[AppState] Initialized', this.getSummary());
    },

    // ==================== STORAGE METHODS ====================

    saveToStorage() {
      try {
        const stateToSave = {
          currentStep: this.currentStep,
          maxStepReached: this.maxStepReached,
          selectedInputMethod: this.selectedInputMethod,
          formData: this.formData,
          videoConfig: this.videoConfig,
          ui: this.ui
        };
        localStorage.setItem('appState', JSON.stringify(stateToSave));
        console.log('[AppState] State saved to localStorage');
      } catch (error) {
        console.error('[AppState] Failed to save state:', error);
      }
    },

    loadFromStorage() {
      try {
        const saved = localStorage.getItem('appState');
        if (saved) {
          const state = JSON.parse(saved);
          Object.assign(this, state);
          console.log('[AppState] State loaded from localStorage');
        }
      } catch (error) {
        console.error('[AppState] Failed to load state:', error);
      }
    },

    clearStorage() {
      localStorage.removeItem('appState');
      console.log('[AppState] Storage cleared');
    },

    // ==================== STEP NAVIGATION ====================

    goToStep(step) {
      if (step < 1 || step > 4) {
        console.warn('[AppState] Invalid step:', step);
        return false;
      }

      // Can only go forward if previous steps are valid
      if (step > this.currentStep && !this.canAdvanceToStep(step)) {
        console.warn('[AppState] Cannot advance to step:', step);
        return false;
      }

      this.currentStep = step;
      this.maxStepReached = Math.max(this.maxStepReached, step);
      console.log('[AppState] Moved to step:', step);
      return true;
    },

    nextStep() {
      return this.goToStep(this.currentStep + 1);
    },

    previousStep() {
      return this.goToStep(this.currentStep - 1);
    },

    canAdvanceToStep(step) {
      switch(step) {
        case 2:
          return this.selectedInputMethod !== null;
        case 3:
          return this.isInputMethodComplete();
        case 4:
          return this.validation.isValid;
        default:
          return true;
      }
    },

    // ==================== INPUT METHOD MANAGEMENT ====================

    selectInputMethod(method) {
      const validMethods = ['document', 'youtube', 'wizard', 'yaml'];
      if (!validMethods.includes(method)) {
        console.warn('[AppState] Invalid input method:', method);
        return false;
      }

      this.selectedInputMethod = method;
      console.log('[AppState] Input method selected:', method);
      return true;
    },

    isInputMethodComplete() {
      if (!this.selectedInputMethod) return false;

      switch(this.selectedInputMethod) {
        case 'document':
          return !!this.formData.document.file;
        case 'youtube':
          return this.formData.youtube.validated;
        case 'wizard':
          return this.formData.wizard.completed;
        case 'yaml':
          return this.formData.yaml.valid;
        default:
          return false;
      }
    },

    // ==================== VIDEO GENERATION ====================

    startGeneration() {
      this.generation.inProgress = true;
      this.generation.currentStage = 'parsing';
      this.generation.progress = 0;
      this.generation.error = null;
      this.updateStageStatus('parsing', 'active');
      console.log('[AppState] Video generation started');
    },

    updateGenerationProgress(stage, progress) {
      this.generation.currentStage = stage;
      this.generation.progress = progress;
      this.updateStageStatus(stage, 'active');
      console.log(`[AppState] Generation progress: ${stage} - ${progress}%`);
    },

    completeGeneration(videoUrl) {
      this.generation.inProgress = false;
      this.generation.currentStage = 'complete';
      this.generation.progress = 100;
      this.generation.videoUrl = videoUrl;
      this.updateStageStatus('complete', 'complete');
      console.log('[AppState] Video generation complete:', videoUrl);
    },

    failGeneration(error) {
      this.generation.inProgress = false;
      this.generation.error = error;
      this.updateStageStatus(this.generation.currentStage, 'error');
      console.error('[AppState] Video generation failed:', error);
    },

    updateStageStatus(stageId, status) {
      const stage = this.generation.stages.find(s => s.id === stageId);
      if (stage) {
        stage.status = status;
      }
    },

    // ==================== VALIDATION ====================

    validate() {
      this.validation.errors = [];
      this.validation.warnings = [];

      // Validate input method completion
      if (!this.isInputMethodComplete()) {
        this.validation.errors.push('Please complete the input method selection');
      }

      // Validate video configuration
      if (!this.videoConfig.title.trim()) {
        this.validation.warnings.push('No title provided - default will be used');
      }

      if (this.videoConfig.slides.length === 0) {
        this.validation.errors.push('No slides configured');
      }

      this.validation.isValid = this.validation.errors.length === 0;
      console.log('[AppState] Validation complete:', this.validation);
      return this.validation.isValid;
    },

    // ==================== UTILITIES ====================

    reset() {
      this.currentStep = 1;
      this.maxStepReached = 1;
      this.selectedInputMethod = null;
      this.formData = {
        document: { file: null, fileName: '', uploadProgress: 0 },
        youtube: { url: '', validated: false, videoInfo: null },
        wizard: { currentQuestion: 0, totalQuestions: 5, answers: [], completed: false },
        yaml: { content: '', parsed: null, valid: false }
      };
      this.videoConfig = {
        title: '',
        aspectRatio: '16:9',
        duration: null,
        language: 'en',
        narration: { enabled: true, style: 'professional', speed: 1.0 },
        slides: [],
        customizations: {}
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
      this.validation = { errors: [], warnings: [], isValid: false };
      this.clearStorage();
      console.log('[AppState] Reset complete');
    },

    getSummary() {
      return {
        step: this.currentStep,
        inputMethod: this.selectedInputMethod,
        inputComplete: this.isInputMethodComplete(),
        valid: this.validation.isValid,
        generating: this.generation.inProgress
      };
    },

    addNotification(type, message, duration = 5000) {
      const notification = {
        id: Date.now(),
        type, // 'success', 'error', 'warning', 'info'
        message,
        timestamp: new Date()
      };
      this.ui.notifications.push(notification);

      if (duration > 0) {
        setTimeout(() => {
          this.removeNotification(notification.id);
        }, duration);
      }
    },

    removeNotification(id) {
      this.ui.notifications = this.ui.notifications.filter(n => n.id !== id);
    }
  });
});
