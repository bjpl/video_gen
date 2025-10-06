/**
 * Extended create.js functionality with template management
 * Integrates TemplateManager class with Alpine.js videoCreator component
 */

// Initialize template manager
const templateManager = new TemplateManager();

/**
 * Add template management methods to videoCreator Alpine component
 */
function extendVideoCreatorWithTemplates(baseCreator) {
    return {
        ...baseCreator,

        // Template state
        showSaveTemplateModal: false,
        showTemplateManager: false,
        showUserTemplates: false,
        userTemplates: [],
        templateForm: {
            name: '',
            description: ''
        },

        // Initialize templates on mount
        async initTemplates() {
            this.userTemplates = templateManager.getAll();
        },

        /**
         * Save current configuration as template
         */
        saveTemplate() {
            const config = this.mode === 'single' ? this.single : this.set;

            if (!this.templateForm.name) {
                window.dispatchEvent(new CustomEvent('show-message', {
                    detail: {
                        message: 'Please enter a template name',
                        type: 'error'
                    }
                }));
                return;
            }

            const template = templateManager.createTemplate(
                this.templateForm.name,
                this.templateForm.description,
                this.mode,
                config
            );

            // Refresh template list
            this.userTemplates = templateManager.getAll();

            // Reset form
            this.templateForm = { name: '', description: '' };
            this.showSaveTemplateModal = false;

            // Show success message
            window.dispatchEvent(new CustomEvent('show-message', {
                detail: {
                    message: `Template "${template.name}" saved successfully!`,
                    type: 'success'
                }
            }));
        },

        /**
         * Load user template
         */
        loadUserTemplate(template) {
            // Set mode
            this.mode = template.mode;
            this.step = 2;

            // Apply configuration
            if (this.mode === 'single') {
                Object.assign(this.single, template.config);
            } else {
                Object.assign(this.set, template.config);
            }

            // Show success message
            window.dispatchEvent(new CustomEvent('show-message', {
                detail: {
                    message: `Template "${template.name}" loaded!`,
                    type: 'success'
                }
            }));
        },

        /**
         * Delete template
         */
        deleteTemplate(id) {
            const template = templateManager.getById(id);
            if (!template) return;

            if (!confirm(`Delete template "${template.name}"?`)) {
                return;
            }

            templateManager.deleteTemplate(id);
            this.userTemplates = templateManager.getAll();

            window.dispatchEvent(new CustomEvent('show-message', {
                detail: {
                    message: `Template deleted`,
                    type: 'success'
                }
            }));
        },

        /**
         * Export template as JSON
         */
        exportTemplate(id) {
            const template = templateManager.exportTemplate(id);
            if (template) {
                window.dispatchEvent(new CustomEvent('show-message', {
                    detail: {
                        message: `Template exported successfully`,
                        type: 'success'
                    }
                }));
            }
        },

        /**
         * Export all templates
         */
        exportAllTemplates() {
            templateManager.exportAll();
            window.dispatchEvent(new CustomEvent('show-message', {
                detail: {
                    message: `All templates exported`,
                    type: 'success'
                }
            }));
        },

        /**
         * Import templates from file
         */
        async importTemplates(event) {
            const file = event.target.files[0];
            if (!file) return;

            try {
                const text = await file.text();
                const data = JSON.parse(text);

                // Check if single template or multiple
                if (Array.isArray(data)) {
                    const imported = templateManager.importAll(data);
                    window.dispatchEvent(new CustomEvent('show-message', {
                        detail: {
                            message: `${imported.length} template(s) imported`,
                            type: 'success'
                        }
                    }));
                } else {
                    const imported = templateManager.importTemplate(data);
                    window.dispatchEvent(new CustomEvent('show-message', {
                        detail: {
                            message: `Template "${imported.name}" imported`,
                            type: 'success'
                        }
                    }));
                }

                this.userTemplates = templateManager.getAll();

                // Reset file input
                event.target.value = '';

            } catch (error) {
                window.dispatchEvent(new CustomEvent('show-message', {
                    detail: {
                        message: `Import failed: ${error.message}`,
                        type: 'error'
                    }
                }));
            }
        },

        /**
         * Clear all templates
         */
        clearAllTemplates() {
            if (!confirm(`Delete ALL templates? This cannot be undone.`)) {
                return;
            }

            templateManager.clearAll();
            this.userTemplates = [];

            window.dispatchEvent(new CustomEvent('show-message', {
                detail: {
                    message: 'All templates cleared',
                    type: 'success'
                }
            }));
        }
    };
}

/**
 * Override the global videoCreator function to include template functionality
 */
if (typeof window !== 'undefined') {
    window.videoCreatorWithTemplates = function() {
        const base = window.videoCreator();
        const extended = extendVideoCreatorWithTemplates(base);

        // Override init to also initialize templates
        const originalInit = extended.init;
        extended.init = async function() {
            if (originalInit) await originalInit.call(this);
            await this.initTemplates();
        };

        return extended;
    };
}
