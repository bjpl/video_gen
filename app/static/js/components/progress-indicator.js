/**
 * ProgressIndicator Alpine.js Component
 *
 * A comprehensive progress tracking component with:
 * - Real-time SSE updates
 * - 7-stage progress visualization
 * - Time elapsed and remaining estimates
 * - Cancellation support
 * - Error handling with retry
 * - Accessibility features (ARIA live regions)
 *
 * @requires Alpine.js
 * @requires /static/js/utils/sse-client.js
 * @requires /static/js/store/app-state.js
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('progressIndicator', (config = {}) => ({
        // ==================== CONFIGURATION ====================

        // API endpoints
        stagesEndpoint: config.stagesEndpoint || '/api/upload/progress-stages',
        streamEndpoint: config.streamEndpoint || '/api/tasks',
        cancelEndpoint: config.cancelEndpoint || '/api/tasks',

        // Callbacks
        onComplete: config.onComplete || null,
        onError: config.onError || null,
        onCancel: config.onCancel || null,

        // ==================== STATE ====================

        // Stage definitions (7 stages)
        stages: [],

        // Current state
        currentStage: null,
        progress: 0,
        stageProgress: 0,
        statusMessage: '',

        // Task tracking
        taskId: null,
        isProcessing: false,
        isComplete: false,
        hasError: false,
        error: null,
        errorDetails: null,

        // Time tracking
        startTime: null,
        timeElapsed: 0,
        timeRemaining: null,
        elapsedTimerInterval: null,

        // Connection state
        sseClient: null,
        connectionState: 'disconnected', // 'disconnected', 'connecting', 'connected', 'reconnecting'
        retryCount: 0,

        // Cancellation
        abortController: null,
        isCancelling: false,
        showCancelConfirm: false,

        // Result data
        resultData: null,
        downloadUrl: null,
        outputFiles: [],

        // ==================== INITIALIZATION ====================

        init() {
            console.log('[ProgressIndicator] Component initialized');

            // Load stage definitions
            this.loadStageDefinitions();

            // Check for task ID in URL
            const urlParams = new URLSearchParams(window.location.search);
            const taskIdFromUrl = urlParams.get('task_id');
            if (taskIdFromUrl) {
                this.startTracking(taskIdFromUrl);
            }

            // Listen for external task start events
            window.addEventListener('start-progress-tracking', (event) => {
                if (event.detail?.taskId) {
                    this.startTracking(event.detail.taskId);
                }
            });

            // Cleanup on page unload
            window.addEventListener('beforeunload', () => {
                this.cleanup();
            });
        },

        // ==================== STAGE DEFINITIONS ====================

        /**
         * Load stage definitions from API
         */
        async loadStageDefinitions() {
            try {
                const response = await fetch(this.stagesEndpoint);
                if (response.ok) {
                    const data = await response.json();
                    this.stages = (data.stages || []).map((stage, index) => ({
                        id: stage.name || `stage_${index}`,
                        name: stage.name || `Stage ${index + 1}`,
                        label: this.formatStageName(stage.name),
                        message: stage.message || '',
                        progress: stage.progress || 0,
                        status: 'pending', // 'pending', 'active', 'complete', 'error'
                        icon: this.getDefaultStageIcon(stage.name)
                    }));
                } else {
                    // Use default stages if API fails
                    this.stages = this.getDefaultStages();
                }
            } catch (error) {
                console.error('[ProgressIndicator] Failed to load stages:', error);
                this.stages = this.getDefaultStages();
            }
        },

        /**
         * Get default stage definitions
         */
        getDefaultStages() {
            return [
                { id: 'upload', name: 'upload', label: 'Uploading', message: 'Uploading file...', progress: 0, status: 'pending', icon: 'cloud-upload' },
                { id: 'validation', name: 'validation', label: 'Validating', message: 'Validating content...', progress: 14, status: 'pending', icon: 'check-circle' },
                { id: 'preview', name: 'preview', label: 'Preview', message: 'Generating preview...', progress: 28, status: 'pending', icon: 'eye' },
                { id: 'parsing', name: 'parsing', label: 'Parsing', message: 'Parsing document...', progress: 42, status: 'pending', icon: 'document-text' },
                { id: 'audio', name: 'audio', label: 'Audio', message: 'Generating audio...', progress: 57, status: 'pending', icon: 'volume-up' },
                { id: 'video', name: 'video', label: 'Video', message: 'Rendering video...', progress: 71, status: 'pending', icon: 'film' },
                { id: 'complete', name: 'complete', label: 'Complete', message: 'Finalizing...', progress: 100, status: 'pending', icon: 'check' }
            ];
        },

        /**
         * Format stage name for display
         */
        formatStageName(name) {
            if (!name) return 'Unknown';
            return name.charAt(0).toUpperCase() + name.slice(1).replace(/_/g, ' ');
        },

        /**
         * Get default icon for a stage
         */
        getDefaultStageIcon(stageName) {
            const iconMap = {
                'upload': 'cloud-upload',
                'validation': 'check-circle',
                'preview': 'eye',
                'parsing': 'document-text',
                'audio': 'volume-up',
                'video': 'film',
                'complete': 'check',
                'rendering': 'film',
                'output': 'download'
            };
            return iconMap[stageName] || 'cog';
        },

        // ==================== PROGRESS TRACKING ====================

        /**
         * Start tracking a task
         * @param {string} taskId - The task ID to track
         */
        async startTracking(taskId) {
            if (!taskId) {
                console.error('[ProgressIndicator] No task ID provided');
                return;
            }

            console.log('[ProgressIndicator] Starting tracking for task:', taskId);

            // Reset state
            this.resetState();
            this.taskId = taskId;
            this.isProcessing = true;
            this.startTime = Date.now();

            // Start elapsed time tracker
            this.startElapsedTimer();

            // Update global store
            this.updateGlobalStore();

            // Connect to SSE stream
            this.connectSSE(taskId);

            // Dispatch event
            this.$dispatch('progress-started', { taskId });
        },

        /**
         * Connect to SSE endpoint for real-time updates
         * @param {string} taskId
         */
        connectSSE(taskId) {
            // Close any existing connection
            if (this.sseClient) {
                this.sseClient.close();
            }

            this.connectionState = 'connecting';

            // Create SSE client with auto-reconnect
            this.sseClient = new SSEClient({
                maxRetries: 5,
                baseDelay: 1000,
                maxDelay: 10000,
                autoReconnect: true
            });

            this.sseClient
                .onOpen(() => {
                    console.log('[ProgressIndicator] SSE connection opened');
                    this.connectionState = 'connected';
                    this.retryCount = 0;
                })
                .onMessage((data) => {
                    this.handleProgressUpdate(data);
                })
                .onError((error) => {
                    console.error('[ProgressIndicator] SSE error:', error);
                    this.connectionState = 'disconnected';

                    // Fall back to polling if SSE fails completely
                    if (this.retryCount >= 3 && this.isProcessing) {
                        this.startPolling(taskId);
                    }
                })
                .onReconnecting((info) => {
                    console.log('[ProgressIndicator] Reconnecting...', info);
                    this.connectionState = 'reconnecting';
                    this.retryCount = info.attempt;
                })
                .onClose((info) => {
                    console.log('[ProgressIndicator] SSE connection closed:', info);
                    this.connectionState = 'disconnected';
                })
                .connect(`${this.streamEndpoint}/${taskId}/stream`);
        },

        /**
         * Fallback polling mechanism
         * @param {string} taskId
         */
        async startPolling(taskId) {
            console.log('[ProgressIndicator] Falling back to polling');

            const poll = async () => {
                if (!this.isProcessing || this.isComplete || this.hasError) {
                    return;
                }

                try {
                    const response = await fetch(`${this.streamEndpoint}/${taskId}`);
                    if (response.ok) {
                        const data = await response.json();
                        this.handleProgressUpdate(data);

                        // Continue polling if not complete
                        if (data.status !== 'complete' && data.status !== 'failed') {
                            setTimeout(poll, 1500);
                        }
                    }
                } catch (error) {
                    console.error('[ProgressIndicator] Polling error:', error);
                    setTimeout(poll, 3000);
                }
            };

            poll();
        },

        /**
         * Handle progress update from SSE or polling
         * @param {Object} data - Progress data
         */
        handleProgressUpdate(data) {
            console.log('[ProgressIndicator] Progress update:', data);

            // Update progress values
            this.progress = data.progress || 0;
            this.statusMessage = data.message || '';

            // Update time estimates
            if (data.time_elapsed !== undefined) {
                this.timeElapsed = data.time_elapsed;
            }
            if (data.time_remaining !== undefined) {
                this.timeRemaining = data.time_remaining;
            } else {
                this.estimateTimeRemaining();
            }

            // Update current stage
            if (data.stage || data.current_stage) {
                this.updateCurrentStage(data.stage || data.current_stage);
            }

            // Handle completion
            if (data.status === 'complete') {
                this.handleCompletion(data);
            }
            // Handle failure
            else if (data.status === 'failed') {
                this.handleError(data.error || 'Generation failed', data.error_details);
            }

            // Store output files if provided
            if (data.output_files) {
                this.outputFiles = data.output_files;
            }

            // Update global store
            this.updateGlobalStore();

            // Dispatch progress event
            this.$dispatch('progress-updated', {
                taskId: this.taskId,
                progress: this.progress,
                stage: this.currentStage,
                message: this.statusMessage
            });
        },

        /**
         * Update current stage and mark previous stages complete
         * @param {string} stageId
         */
        updateCurrentStage(stageId) {
            let foundCurrent = false;

            this.stages = this.stages.map(stage => {
                if (stage.id === stageId || stage.name === stageId) {
                    foundCurrent = true;
                    this.currentStage = stage;
                    return { ...stage, status: 'active' };
                } else if (!foundCurrent) {
                    return { ...stage, status: 'complete' };
                } else {
                    return { ...stage, status: 'pending' };
                }
            });
        },

        // ==================== TIME TRACKING ====================

        /**
         * Start elapsed time timer
         */
        startElapsedTimer() {
            if (this.elapsedTimerInterval) {
                clearInterval(this.elapsedTimerInterval);
            }

            this.elapsedTimerInterval = setInterval(() => {
                if (this.startTime && this.isProcessing && !this.isComplete) {
                    this.timeElapsed = Math.floor((Date.now() - this.startTime) / 1000);
                    this.estimateTimeRemaining();
                }
            }, 1000);
        },

        /**
         * Estimate time remaining based on progress
         */
        estimateTimeRemaining() {
            if (this.progress > 5 && this.progress < 100) {
                const elapsed = (Date.now() - this.startTime) / 1000;
                const estimatedTotal = elapsed / (this.progress / 100);
                this.timeRemaining = Math.max(0, Math.round(estimatedTotal - elapsed));
            }
        },

        /**
         * Format seconds to MM:SS display
         * @param {number} seconds
         * @returns {string}
         */
        formatTime(seconds) {
            if (seconds === null || seconds === undefined) {
                return '--:--';
            }

            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            return `${mins}:${secs.toString().padStart(2, '0')}`;
        },

        /**
         * Format time remaining with approximate indicator
         * @returns {string}
         */
        formatTimeRemaining() {
            if (this.timeRemaining === null) {
                return 'Calculating...';
            }
            return `~${this.formatTime(this.timeRemaining)}`;
        },

        // ==================== COMPLETION & ERROR HANDLING ====================

        /**
         * Handle successful completion
         * @param {Object} data
         */
        handleCompletion(data) {
            console.log('[ProgressIndicator] Generation complete');

            this.isProcessing = false;
            this.isComplete = true;
            this.progress = 100;

            // Mark all stages complete
            this.stages = this.stages.map(stage => ({
                ...stage,
                status: 'complete'
            }));

            // Store result data
            this.resultData = data;
            this.downloadUrl = data.video_url || data.download_url;
            this.outputFiles = data.output_files || [];

            // Stop timer
            this.stopElapsedTimer();

            // Close SSE
            this.cleanup();

            // Update global store
            if (Alpine.store('appState')) {
                Alpine.store('appState').generation.isComplete = true;
                Alpine.store('appState').generation.videoUrl = this.downloadUrl;
            }

            // Callback
            if (this.onComplete && typeof this.onComplete === 'function') {
                this.onComplete(data);
            }

            // Dispatch event
            this.$dispatch('generation-complete', {
                taskId: this.taskId,
                downloadUrl: this.downloadUrl,
                duration: this.timeElapsed,
                outputFiles: this.outputFiles
            });
        },

        /**
         * Handle error
         * @param {string} errorMessage
         * @param {string} errorDetails
         */
        handleError(errorMessage, errorDetails = null) {
            console.error('[ProgressIndicator] Error:', errorMessage);

            this.isProcessing = false;
            this.hasError = true;
            this.error = errorMessage;
            this.errorDetails = errorDetails;

            // Mark current stage as error
            if (this.currentStage) {
                const idx = this.stages.findIndex(s => s.id === this.currentStage.id);
                if (idx >= 0) {
                    this.stages[idx].status = 'error';
                }
            }

            // Stop timer
            this.stopElapsedTimer();

            // Close SSE
            this.cleanup();

            // Update global store
            if (Alpine.store('appState')) {
                Alpine.store('appState').generation.error = errorMessage;
                Alpine.store('appState').generation.inProgress = false;
            }

            // Callback
            if (this.onError && typeof this.onError === 'function') {
                this.onError(errorMessage, errorDetails);
            }

            // Dispatch event
            this.$dispatch('generation-error', {
                taskId: this.taskId,
                error: errorMessage,
                details: errorDetails
            });
        },

        // ==================== CANCELLATION ====================

        /**
         * Show cancel confirmation
         */
        promptCancel() {
            this.showCancelConfirm = true;
        },

        /**
         * Hide cancel confirmation
         */
        dismissCancel() {
            this.showCancelConfirm = false;
        },

        /**
         * Cancel the current operation
         */
        async cancelOperation() {
            if (!this.taskId || this.isCancelling) {
                return;
            }

            this.isCancelling = true;
            this.showCancelConfirm = false;

            try {
                const response = await fetch(`${this.cancelEndpoint}/${this.taskId}/cancel`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                if (response.ok) {
                    this.isProcessing = false;
                    this.statusMessage = 'Operation cancelled';

                    // Cleanup
                    this.cleanup();

                    // Callback
                    if (this.onCancel && typeof this.onCancel === 'function') {
                        this.onCancel(this.taskId);
                    }

                    // Dispatch event
                    this.$dispatch('generation-cancelled', { taskId: this.taskId });
                } else {
                    console.error('[ProgressIndicator] Cancel request failed');
                }
            } catch (error) {
                console.error('[ProgressIndicator] Cancel error:', error);
            } finally {
                this.isCancelling = false;
            }
        },

        // ==================== RETRY ====================

        /**
         * Retry failed operation
         */
        retry() {
            if (this.taskId) {
                // Dispatch retry event - parent should handle creating new task
                this.$dispatch('generation-retry', { taskId: this.taskId });
            }

            // Reset error state
            this.hasError = false;
            this.error = null;
            this.errorDetails = null;
        },

        // ==================== UI HELPERS ====================

        /**
         * Get icon HTML for a stage
         * @param {Object} stage
         * @returns {string}
         */
        getStageIcon(stage) {
            const iconMap = {
                'cloud-upload': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>',
                'check-circle': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>',
                'eye': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path></svg>',
                'document-text': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>',
                'volume-up': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"></path></svg>',
                'film': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 4v16M17 4v16M3 8h4m10 0h4M3 12h18M3 16h4m10 0h4M4 20h16a1 1 0 001-1V5a1 1 0 00-1-1H4a1 1 0 00-1 1v14a1 1 0 001 1z"></path></svg>',
                'check': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>',
                'download': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>',
                'cog': '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>'
            };
            return iconMap[stage.icon] || iconMap['cog'];
        },

        /**
         * Get status indicator text for a stage
         * @param {Object} stage
         * @returns {string}
         */
        getStageIndicator(stage) {
            switch (stage.status) {
                case 'complete': return '<span class="text-green-600">&#10003;</span>'; // Checkmark
                case 'active': return '<span class="text-blue-600 animate-pulse">&#9679;</span>'; // Filled circle
                case 'error': return '<span class="text-red-600">&#10007;</span>'; // X
                default: return '<span class="text-gray-400">&#9675;</span>'; // Empty circle
            }
        },

        /**
         * Get CSS class for a stage
         * @param {Object} stage
         * @returns {string}
         */
        getStageClass(stage) {
            switch (stage.status) {
                case 'complete':
                    return 'progress-stage--complete';
                case 'active':
                    return 'progress-stage--active';
                case 'error':
                    return 'progress-stage--error';
                default:
                    return 'progress-stage--pending';
            }
        },

        /**
         * Get connection status for display
         * @returns {string}
         */
        getConnectionStatus() {
            switch (this.connectionState) {
                case 'connected': return 'Live';
                case 'connecting': return 'Connecting...';
                case 'reconnecting': return 'Reconnecting...';
                default: return 'Offline';
            }
        },

        /**
         * Get connection status CSS class
         * @returns {string}
         */
        getConnectionClass() {
            switch (this.connectionState) {
                case 'connected': return 'connection-status--live';
                case 'connecting':
                case 'reconnecting': return 'connection-status--reconnecting';
                default: return 'connection-status--offline';
            }
        },

        // ==================== STATE MANAGEMENT ====================

        /**
         * Reset component state
         */
        resetState() {
            this.currentStage = null;
            this.progress = 0;
            this.stageProgress = 0;
            this.statusMessage = '';
            this.isProcessing = false;
            this.isComplete = false;
            this.hasError = false;
            this.error = null;
            this.errorDetails = null;
            this.startTime = null;
            this.timeElapsed = 0;
            this.timeRemaining = null;
            this.connectionState = 'disconnected';
            this.retryCount = 0;
            this.isCancelling = false;
            this.showCancelConfirm = false;
            this.resultData = null;
            this.downloadUrl = null;
            this.outputFiles = [];

            // Reset stage statuses
            this.stages = this.stages.map(stage => ({
                ...stage,
                status: 'pending'
            }));
        },

        /**
         * Stop tracking
         */
        stopTracking() {
            this.isProcessing = false;
            this.cleanup();
        },

        /**
         * Cleanup resources
         */
        cleanup() {
            // Close SSE connection
            if (this.sseClient) {
                this.sseClient.close();
                this.sseClient = null;
            }

            // Stop elapsed timer
            this.stopElapsedTimer();
        },

        /**
         * Stop elapsed time timer
         */
        stopElapsedTimer() {
            if (this.elapsedTimerInterval) {
                clearInterval(this.elapsedTimerInterval);
                this.elapsedTimerInterval = null;
            }
        },

        /**
         * Update global Alpine store
         */
        updateGlobalStore() {
            if (Alpine.store('appState')) {
                Alpine.store('appState').generation = {
                    ...Alpine.store('appState').generation,
                    taskId: this.taskId,
                    inProgress: this.isProcessing,
                    progress: this.progress,
                    currentStage: this.currentStage?.id || null,
                    isComplete: this.isComplete,
                    error: this.error
                };
            }
        },

        /**
         * Destroy component
         */
        destroy() {
            this.cleanup();
        }
    }));
});
