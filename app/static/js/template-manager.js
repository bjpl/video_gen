/**
 * Template Management System
 * Handles saving, loading, and managing user video generation templates
 */

class TemplateManager {
    constructor() {
        this.storageKey = 'video_gen_templates';
        this.templates = this.loadTemplates();
    }

    /**
     * Load all templates from localStorage
     */
    loadTemplates() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            return [];
        }
    }

    /**
     * Save templates to localStorage
     */
    saveTemplates() {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(this.templates));
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Create a new template from current configuration
     */
    createTemplate(name, description, mode, config) {
        const template = {
            id: Date.now().toString(),
            name: name,
            description: description,
            mode: mode,
            config: JSON.parse(JSON.stringify(config)), // Deep clone
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        this.templates.push(template);
        this.saveTemplates();
        return template;
    }

    /**
     * Get all templates
     */
    getAll() {
        return this.templates;
    }

    /**
     * Get template by ID
     */
    getById(id) {
        return this.templates.find(t => t.id === id);
    }

    /**
     * Update existing template
     */
    updateTemplate(id, updates) {
        const index = this.templates.findIndex(t => t.id === id);
        if (index === -1) return false;

        this.templates[index] = {
            ...this.templates[index],
            ...updates,
            updatedAt: new Date().toISOString()
        };

        this.saveTemplates();
        return true;
    }

    /**
     * Delete template
     */
    deleteTemplate(id) {
        const index = this.templates.findIndex(t => t.id === id);
        if (index === -1) return false;

        this.templates.splice(index, 1);
        this.saveTemplates();
        return true;
    }

    /**
     * Export template as JSON
     */
    exportTemplate(id) {
        const template = this.getById(id);
        if (!template) return null;

        const json = JSON.stringify(template, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `template-${template.name.replace(/\s+/g, '-').toLowerCase()}.json`;
        a.click();

        URL.revokeObjectURL(url);
        return template;
    }

    /**
     * Import template from JSON
     */
    importTemplate(jsonData) {
        try {
            const template = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;

            // Generate new ID to avoid conflicts
            template.id = Date.now().toString();
            template.createdAt = new Date().toISOString();
            template.updatedAt = new Date().toISOString();

            this.templates.push(template);
            this.saveTemplates();
            return template;
        } catch (error) {
            return null;
        }
    }

    /**
     * Export all templates
     */
    exportAll() {
        const json = JSON.stringify(this.templates, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `video-templates-${new Date().toISOString().split('T')[0]}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    /**
     * Import multiple templates
     */
    importAll(jsonData) {
        try {
            const templates = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;

            if (!Array.isArray(templates)) {
                throw new Error('Invalid template data: expected array');
            }

            const imported = [];
            templates.forEach(template => {
                template.id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
                template.createdAt = new Date().toISOString();
                template.updatedAt = new Date().toISOString();
                this.templates.push(template);
                imported.push(template);
            });

            this.saveTemplates();
            return imported;
        } catch (error) {
            return [];
        }
    }

    /**
     * Clear all templates (with confirmation)
     */
    clearAll() {
        this.templates = [];
        this.saveTemplates();
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = TemplateManager;
}
