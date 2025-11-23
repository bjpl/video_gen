/**
 * DragDropZone Alpine.js Component
 *
 * A feature-rich drag-drop file upload component with:
 * - Visual drag/drop zone with hover effects
 * - File type filtering (.md, .txt, .rst)
 * - Size validation (10MB limit)
 * - Real-time validation feedback
 * - Integration with /api/validate/document API
 * - Preview generation trigger
 *
 * @requires Alpine.js
 * @requires /static/js/store/app-state.js
 */

document.addEventListener('alpine:init', () => {
    Alpine.data('dragDropZone', (config = {}) => ({
        // ==================== CONFIGURATION ====================

        // Allowed file types
        allowedTypes: config.allowedTypes || ['.md', '.txt', '.rst', '.markdown'],
        allowedMimeTypes: config.allowedMimeTypes || [
            'text/markdown',
            'text/plain',
            'text/x-rst',
            'text/x-markdown',
            'application/octet-stream' // For .md files on some systems
        ],

        // Maximum file size in bytes (default 10MB)
        maxFileSize: config.maxFileSize || 10 * 1024 * 1024,

        // API endpoints
        validateEndpoint: config.validateEndpoint || '/api/validate/document',
        previewEndpoint: config.previewEndpoint || '/api/preview/document',

        // Callback functions
        onFileSelected: config.onFileSelected || null,
        onValidationComplete: config.onValidationComplete || null,
        onPreviewReady: config.onPreviewReady || null,
        onError: config.onError || null,

        // ==================== STATE ====================

        // Drag state
        isDragging: false,
        dragCounter: 0,

        // File state
        file: null,
        fileName: '',
        fileSize: 0,
        fileType: '',

        // Upload/validation state
        isUploading: false,
        uploadProgress: 0,
        isValidating: false,
        validationComplete: false,

        // Validation results
        isValid: false,
        errors: [],
        warnings: [],

        // Preview state
        isGeneratingPreview: false,
        preview: null,

        // UI state
        showDropZone: true,
        showFileInfo: false,
        showValidationResult: false,
        showPreview: false,

        // ==================== INITIALIZATION ====================

        init() {
            console.log('[DragDropZone] Component initialized');

            // Restore state from global store if available
            if (Alpine.store('appState')?.formData?.document?.file) {
                const storedData = Alpine.store('appState').formData.document;
                this.fileName = storedData.fileName || '';
                // Note: File object cannot be restored from localStorage
            }
        },

        // ==================== DRAG EVENT HANDLERS ====================

        /**
         * Handle dragenter event
         * Uses counter to track nested drag events
         */
        handleDragEnter(event) {
            event.preventDefault();
            event.stopPropagation();
            this.dragCounter++;
            this.isDragging = true;
        },

        /**
         * Handle dragleave event
         * Uses counter to prevent flickering on nested elements
         */
        handleDragLeave(event) {
            event.preventDefault();
            event.stopPropagation();
            this.dragCounter--;
            if (this.dragCounter === 0) {
                this.isDragging = false;
            }
        },

        /**
         * Handle dragover event
         * Required to allow drop
         */
        handleDragOver(event) {
            event.preventDefault();
            event.stopPropagation();
            // Set the drop effect
            event.dataTransfer.dropEffect = 'copy';
        },

        /**
         * Handle drop event
         * Process dropped files
         */
        handleDrop(event) {
            event.preventDefault();
            event.stopPropagation();

            this.isDragging = false;
            this.dragCounter = 0;

            const files = event.dataTransfer?.files;
            if (files && files.length > 0) {
                // Only process the first file for single file mode
                this.processFile(files[0]);
            }
        },

        // ==================== FILE INPUT HANDLER ====================

        /**
         * Handle file selection via input element
         */
        handleFileSelect(event) {
            const files = event.target.files;
            if (files && files.length > 0) {
                this.processFile(files[0]);
            }
        },

        /**
         * Trigger file input click programmatically
         */
        triggerFileInput() {
            this.$refs.fileInput?.click();
        },

        // ==================== FILE PROCESSING ====================

        /**
         * Process selected/dropped file
         * Validates type and size before API validation
         */
        async processFile(file) {
            console.log('[DragDropZone] Processing file:', file.name);

            // Reset state
            this.resetState();

            // Store file info
            this.file = file;
            this.fileName = file.name;
            this.fileSize = file.size;
            this.fileType = file.type || this.getFileTypeFromExtension(file.name);

            // Update UI
            this.showDropZone = false;
            this.showFileInfo = true;

            // Client-side validation
            const clientValidation = this.validateFileClient(file);
            if (!clientValidation.valid) {
                this.errors = clientValidation.errors;
                this.isValid = false;
                this.validationComplete = true;
                this.showValidationResult = true;
                this.notifyError(clientValidation.errors.join(', '));
                return;
            }

            // Update global store
            this.updateGlobalStore();

            // Notify callback
            if (this.onFileSelected && typeof this.onFileSelected === 'function') {
                this.onFileSelected(file);
            }

            // Server-side validation
            await this.validateFileServer(file);
        },

        /**
         * Get file type from extension
         */
        getFileTypeFromExtension(filename) {
            const ext = filename.split('.').pop()?.toLowerCase();
            const typeMap = {
                'md': 'text/markdown',
                'markdown': 'text/markdown',
                'txt': 'text/plain',
                'rst': 'text/x-rst'
            };
            return typeMap[ext] || 'application/octet-stream';
        },

        // ==================== VALIDATION ====================

        /**
         * Client-side file validation
         * Checks file type and size before upload
         */
        validateFileClient(file) {
            const errors = [];

            // Check file extension
            const extension = '.' + file.name.split('.').pop()?.toLowerCase();
            if (!this.allowedTypes.includes(extension)) {
                errors.push(`File type "${extension}" is not supported. Allowed types: ${this.allowedTypes.join(', ')}`);
            }

            // Check file size
            if (file.size > this.maxFileSize) {
                const maxSizeMB = (this.maxFileSize / (1024 * 1024)).toFixed(1);
                const fileSizeMB = (file.size / (1024 * 1024)).toFixed(1);
                errors.push(`File size (${fileSizeMB}MB) exceeds maximum allowed size (${maxSizeMB}MB)`);
            }

            // Check if file is empty
            if (file.size === 0) {
                errors.push('File is empty. Please select a file with content.');
            }

            return {
                valid: errors.length === 0,
                errors: errors
            };
        },

        /**
         * Server-side file validation via API
         */
        async validateFileServer(file) {
            this.isValidating = true;
            this.showValidationResult = false;

            try {
                const formData = new FormData();
                formData.append('file', file);

                const response = await fetch(this.validateEndpoint, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok) {
                    this.isValid = result.valid !== false;
                    this.errors = result.errors || [];
                    this.warnings = result.warnings || [];

                    // Store sanitized filename if provided
                    if (result.sanitized_filename) {
                        this.fileName = result.sanitized_filename;
                    }

                    // Notify callback
                    if (this.onValidationComplete && typeof this.onValidationComplete === 'function') {
                        this.onValidationComplete({
                            valid: this.isValid,
                            errors: this.errors,
                            warnings: this.warnings,
                            file: file
                        });
                    }

                    // Auto-generate preview if valid
                    if (this.isValid && this.errors.length === 0) {
                        await this.generatePreview(file);
                    }
                } else {
                    this.isValid = false;
                    this.errors = [result.detail || 'Validation failed. Please try again.'];
                    this.notifyError(this.errors[0]);
                }
            } catch (error) {
                console.error('[DragDropZone] Validation error:', error);
                this.isValid = false;
                this.errors = ['Failed to validate file. Please check your connection and try again.'];
                this.notifyError(this.errors[0]);
            } finally {
                this.isValidating = false;
                this.validationComplete = true;
                this.showValidationResult = true;
                this.updateGlobalStore();
            }
        },

        // ==================== PREVIEW GENERATION ====================

        /**
         * Generate document preview via API
         */
        async generatePreview(file) {
            this.isGeneratingPreview = true;

            try {
                const formData = new FormData();
                formData.append('file', file);

                const response = await fetch(this.previewEndpoint, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok) {
                    // Extract preview from nested response structure
                    const previewData = result.preview || result;
                    this.preview = previewData;
                    this.showPreview = true;

                    // Notify callback
                    if (this.onPreviewReady && typeof this.onPreviewReady === 'function') {
                        this.onPreviewReady(previewData);
                    }

                    // Dispatch custom event for preview-panel component
                    window.dispatchEvent(new CustomEvent('preview-ready', {
                        detail: { preview: previewData, type: 'document', file: file }
                    }));

                    // Also dispatch Alpine event for local components
                    this.$dispatch('preview-ready', { preview: previewData, file: file });
                } else {
                    // Preview generation failed but file is still valid
                    console.warn('[DragDropZone] Preview generation failed:', result.detail);
                    this.warnings.push('Preview generation unavailable. You can still proceed.');
                }
            } catch (error) {
                console.error('[DragDropZone] Preview error:', error);
                this.warnings.push('Preview generation unavailable. You can still proceed.');
            } finally {
                this.isGeneratingPreview = false;
            }
        },

        /**
         * Manually trigger preview generation
         */
        async refreshPreview() {
            if (this.file && this.isValid) {
                await this.generatePreview(this.file);
            }
        },

        // ==================== STATE MANAGEMENT ====================

        /**
         * Reset component state
         */
        resetState() {
            this.file = null;
            this.fileName = '';
            this.fileSize = 0;
            this.fileType = '';
            this.isUploading = false;
            this.uploadProgress = 0;
            this.isValidating = false;
            this.validationComplete = false;
            this.isValid = false;
            this.errors = [];
            this.warnings = [];
            this.isGeneratingPreview = false;
            this.preview = null;
            this.showDropZone = true;
            this.showFileInfo = false;
            this.showValidationResult = false;
            this.showPreview = false;
        },

        /**
         * Remove current file and reset
         */
        removeFile() {
            this.resetState();
            this.updateGlobalStore();

            // Clear file input
            if (this.$refs.fileInput) {
                this.$refs.fileInput.value = '';
            }

            // Dispatch event
            this.$dispatch('file-removed');
        },

        /**
         * Update global Alpine store
         */
        updateGlobalStore() {
            if (Alpine.store('appState')) {
                Alpine.store('appState').formData.document = {
                    file: this.file,
                    fileName: this.fileName,
                    uploadProgress: this.uploadProgress,
                    isValid: this.isValid,
                    errors: this.errors,
                    warnings: this.warnings,
                    preview: this.preview
                };
            }
        },

        // ==================== UTILITY METHODS ====================

        /**
         * Format file size for display
         */
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';

            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));

            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        /**
         * Get file icon based on extension
         */
        getFileIcon() {
            const ext = this.fileName.split('.').pop()?.toLowerCase();
            const iconMap = {
                'md': '📝',
                'markdown': '📝',
                'txt': '📄',
                'rst': '📑'
            };
            return iconMap[ext] || '📁';
        },

        /**
         * Get status indicator class
         */
        getStatusClass() {
            if (this.isValidating || this.isGeneratingPreview) {
                return 'status-validating';
            }
            if (this.validationComplete && this.isValid && this.errors.length === 0) {
                return 'status-valid';
            }
            if (this.errors.length > 0) {
                return 'status-error';
            }
            if (this.warnings.length > 0) {
                return 'status-warning';
            }
            return '';
        },

        /**
         * Send error notification
         */
        notifyError(message) {
            if (this.onError && typeof this.onError === 'function') {
                this.onError(message);
            }

            // Also notify via global store
            if (Alpine.store('appState')?.addNotification) {
                Alpine.store('appState').addNotification('error', message);
            }
        },

        /**
         * Check if file can proceed to next step
         */
        canProceed() {
            return this.validationComplete && this.isValid && this.errors.length === 0;
        },

        /**
         * Get accepted file types string for input element
         */
        getAcceptedTypes() {
            return this.allowedTypes.join(',');
        }
    }));
});
