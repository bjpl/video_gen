# Component Pseudocode - SPARC Phase P

**Date:** November 22, 2025
**Version:** 1.0.0
**Status:** Pseudocode Complete
**Author:** Architecture Agent

---

## 1. Overview

This document contains pseudocode definitions for all new and enhanced Alpine.js components in the frontend modernization project. Each component includes:
- State definition
- Method signatures
- Event handling
- Data flow

---

## 2. Core Components

### 2.1 DragDropZone Component

**Purpose:** Handle file drag-and-drop with visual feedback and validation

```pseudocode
COMPONENT DragDropZone:
    // ============= STATE =============
    STATE:
        file: null                    // Selected File object
        fileName: ""                  // Display name
        fileContent: ""               // Read content (text or base64)
        fileType: ""                  // 'text', 'pdf', 'docx'

        dragActive: false             // Currently dragging over
        isReading: false              // File being read
        isValidating: false           // Validation in progress

        validationStatus: 'idle'      // 'idle' | 'valid' | 'invalid'
        validationError: null         // Error message
        validationSuggestion: null    // Helpful suggestion

        preview: null                 // Preview data from API

    // ============= PROPS =============
    PROPS:
        acceptTypes: ['.md', '.txt', '.pdf', '.docx']
        maxSizeBytes: 10 * 1024 * 1024  // 10MB
        inputMethod: 'document'          // 'document' | 'yaml'

    // ============= COMPUTED =============
    GET acceptString():
        IF inputMethod == 'yaml':
            RETURN '.yaml,.yml'
        RETURN acceptTypes.join(',')

    GET maxSizeDisplay():
        RETURN (maxSizeBytes / 1024 / 1024) + 'MB'

    GET hasFile():
        RETURN file != null AND fileContent != ''

    GET statusClass():
        SWITCH validationStatus:
            CASE 'valid': RETURN 'border-green-500 bg-green-50'
            CASE 'invalid': RETURN 'border-red-500 bg-red-50'
            DEFAULT: RETURN 'border-gray-300'

    // ============= METHODS =============
    METHOD init():
        // Initialize component
        LISTEN FOR 'dragenter' ON document
        LISTEN FOR 'dragleave' ON document
        LISTEN FOR 'drop' ON document
        PREVENT default drag behavior globally

    METHOD handleDragEnter(event):
        event.preventDefault()
        dragActive = true

    METHOD handleDragLeave(event):
        event.preventDefault()
        // Only deactivate if leaving drop zone entirely
        IF event.relatedTarget NOT IN dropZone:
            dragActive = false

    METHOD handleDrop(event):
        event.preventDefault()
        dragActive = false

        files = event.dataTransfer.files
        IF files.length > 0:
            processFile(files[0])

    METHOD handleFileSelect(event):
        files = event.target.files
        IF files.length > 0:
            processFile(files[0])
        // Reset input for same-file selection
        event.target.value = ''

    METHOD processFile(selectedFile):
        // Reset state
        clearState()

        // Extract extension
        extension = '.' + selectedFile.name.split('.').pop().toLowerCase()

        // Validate file type
        IF extension NOT IN allowedTypes():
            setError(
                'Invalid file type: ' + extension,
                'Supported types: ' + acceptString
            )
            RETURN

        // Validate file size
        IF selectedFile.size > maxSizeBytes:
            setError(
                'File too large: ' + formatBytes(selectedFile.size),
                'Maximum size: ' + maxSizeDisplay
            )
            RETURN

        // Store file metadata
        file = selectedFile
        fileName = selectedFile.name
        isReading = true

        TRY:
            // Read file content
            IF extension IN ['.pdf', '.docx']:
                fileContent = AWAIT readAsBase64(selectedFile)
                fileType = extension.substring(1)
            ELSE:
                fileContent = AWAIT readAsText(selectedFile)
                fileType = 'text'

                // Validate YAML syntax if applicable
                IF inputMethod == 'yaml':
                    IF NOT isValidYaml(fileContent):
                        setError(
                            'Invalid YAML syntax',
                            'Check for proper indentation and key-value pairs'
                        )
                        clearFile()
                        RETURN

            // Validate via API
            validationResult = AWAIT validateFile()

            IF validationResult.valid:
                validationStatus = 'valid'
                // Fetch preview
                preview = AWAIT fetchPreview()
                EMIT 'file-ready' WITH {file, fileContent, preview}
            ELSE:
                setError(
                    validationResult.error,
                    validationResult.suggestion
                )

        CATCH error:
            setError('Failed to read file', error.message)

        FINALLY:
            isReading = false

    METHOD readAsText(file):
        RETURN NEW Promise((resolve, reject) =>
            reader = NEW FileReader()
            reader.onload = (e) => resolve(e.target.result)
            reader.onerror = () => reject(NEW Error('Read failed'))
            reader.readAsText(file, 'UTF-8')
        )

    METHOD readAsBase64(file):
        RETURN NEW Promise((resolve, reject) =>
            reader = NEW FileReader()
            reader.onload = (e) =>
                // Extract base64 from data URL
                base64 = e.target.result.split(',')[1]
                resolve(base64)
            reader.onerror = () => reject(NEW Error('Read failed'))
            reader.readAsDataURL(file)
        )

    METHOD validateFile():
        isValidating = true

        TRY:
            response = AWAIT fetch('/api/validate/document', {
                method: 'POST',
                body: createFormData()
            })
            RETURN AWAIT response.json()
        FINALLY:
            isValidating = false

    METHOD fetchPreview():
        response = AWAIT fetch('/api/preview/document', {
            method: 'POST',
            body: createFormData()
        })
        RETURN AWAIT response.json()

    METHOD createFormData():
        formData = NEW FormData()
        formData.append('file', file)
        formData.append('content', fileContent)
        formData.append('file_type', fileType)
        RETURN formData

    METHOD isValidYaml(content):
        lines = content.split('\n')
        FOR line IN lines:
            trimmed = line.trim()
            IF trimmed AND NOT trimmed.startsWith('#'):
                IF trimmed.includes(':') OR trimmed.startsWith('-'):
                    RETURN true
        RETURN false

    METHOD setError(message, suggestion):
        validationStatus = 'invalid'
        validationError = message
        validationSuggestion = suggestion
        EMIT 'validation-error' WITH {message, suggestion}

    METHOD clearFile():
        file = null
        fileName = ''
        fileContent = ''
        fileType = ''
        preview = null

    METHOD clearState():
        clearFile()
        validationStatus = 'idle'
        validationError = null
        validationSuggestion = null

    METHOD formatBytes(bytes):
        IF bytes < 1024: RETURN bytes + ' B'
        IF bytes < 1024 * 1024: RETURN (bytes / 1024).toFixed(1) + ' KB'
        RETURN (bytes / 1024 / 1024).toFixed(1) + ' MB'

    METHOD allowedTypes():
        IF inputMethod == 'yaml':
            RETURN ['.yaml', '.yml']
        RETURN ['.txt', '.md', '.pdf', '.docx']
```

---

### 2.2 ValidationFeedback Component

**Purpose:** Display real-time validation feedback with accessibility

```pseudocode
COMPONENT ValidationFeedback:
    // ============= STATE =============
    STATE:
        status: 'pristine'            // 'pristine' | 'validating' | 'valid' | 'invalid' | 'warning'
        errorMessage: null
        suggestion: null
        debounceTimer: null

    // ============= PROPS =============
    PROPS:
        fieldName: string             // Validator key (e.g., 'url', 'video_id')
        value: any                    // Current field value
        debounceMs: 500               // Debounce delay
        showIcon: true                // Show status icon
        showSuggestion: true          // Show suggestion on error

    // ============= COMPUTED =============
    GET icon():
        SWITCH status:
            CASE 'validating': RETURN '⏳'
            CASE 'valid': RETURN '✅'
            CASE 'invalid': RETURN '❌'
            CASE 'warning': RETURN '⚠️'
            DEFAULT: RETURN ''

    GET ariaLabel():
        SWITCH status:
            CASE 'valid': RETURN fieldName + ' is valid'
            CASE 'invalid': RETURN fieldName + ' has error: ' + errorMessage
            CASE 'warning': RETURN fieldName + ' has warning: ' + errorMessage
            DEFAULT: RETURN ''

    GET inputClass():
        SWITCH status:
            CASE 'valid': RETURN 'border-green-500 focus:ring-green-500'
            CASE 'invalid': RETURN 'border-red-500 focus:ring-red-500'
            CASE 'warning': RETURN 'border-yellow-500 focus:ring-yellow-500'
            DEFAULT: RETURN 'border-gray-300 focus:ring-blue-500'

    // ============= METHODS =============
    METHOD init():
        // Watch for value changes
        $watch('value', () => debouncedValidate())

    METHOD debouncedValidate():
        // Clear existing timer
        IF debounceTimer:
            clearTimeout(debounceTimer)

        // Handle empty value
        IF NOT value OR value.trim() == '':
            status = 'pristine'
            errorMessage = null
            suggestion = null
            RETURN

        // Show validating state
        status = 'validating'

        // Set new timer
        debounceTimer = setTimeout(() => validate(), debounceMs)

    METHOD validate():
        // Get validator for this field
        validator = window.formValidator
        IF NOT validator:
            RETURN

        // Run validation
        result = validator.validateField(fieldName, value)

        IF result == null:
            // Valid
            status = 'valid'
            errorMessage = null
            suggestion = null
            EMIT 'validation-success' WITH {fieldName, value}
        ELSE:
            // Invalid
            status = 'invalid'
            errorMessage = result
            suggestion = getSuggestion(fieldName, value, result)
            EMIT 'validation-error' WITH {fieldName, error: result, suggestion}

        // Update ARIA attributes
        updateAriaAttributes()

    METHOD getSuggestion(fieldName, value, error):
        // Context-aware suggestions
        SWITCH fieldName:
            CASE 'youtube_url':
                IF NOT value.includes('youtube') AND NOT value.includes('youtu.be'):
                    RETURN 'Try pasting a YouTube URL like https://youtube.com/watch?v=...'
                RETURN 'Check that the video ID is exactly 11 characters'

            CASE 'url':
                IF NOT value.startsWith('http'):
                    RETURN 'URLs must start with http:// or https://'
                RETURN 'Verify the URL is accessible'

            CASE 'video_id':
                RETURN 'Use only letters, numbers, hyphens, and underscores'

            DEFAULT:
                RETURN null

    METHOD updateAriaAttributes():
        // Find associated input element
        input = document.querySelector('[x-validate="' + fieldName + '"]')
        IF NOT input:
            RETURN

        IF status == 'invalid' OR status == 'warning':
            input.setAttribute('aria-invalid', 'true')
            input.setAttribute('aria-describedby', getErrorId())
        ELSE:
            input.setAttribute('aria-invalid', 'false')
            input.removeAttribute('aria-describedby')

    METHOD getErrorId():
        RETURN fieldName + '-error-' + uniqueId()

    METHOD clearValidation():
        status = 'pristine'
        errorMessage = null
        suggestion = null
        IF debounceTimer:
            clearTimeout(debounceTimer)
```

---

### 2.3 PreviewPanel Component

**Purpose:** Display content preview with collapsible sections

```pseudocode
COMPONENT PreviewPanel:
    // ============= STATE =============
    STATE:
        isLoading: false
        isCollapsed: false
        expandedSections: []          // Track which sections are expanded

    // ============= PROPS =============
    PROPS:
        type: string                  // 'document' | 'youtube'
        preview: object               // Preview data from API
        initialCollapsed: false

    // ============= COMPUTED =============
    GET hasPreview():
        RETURN preview != null

    GET title():
        IF type == 'document':
            RETURN preview?.title OR 'Untitled Document'
        RETURN preview?.title OR 'YouTube Video'

    GET sectionCount():
        IF type == 'document':
            RETURN preview?.sections?.length OR 0
        RETURN preview?.chapters?.length OR 0

    GET estimatedDuration():
        duration = preview?.estimated_duration OR 0
        minutes = Math.floor(duration / 60)
        seconds = duration % 60
        RETURN minutes + ':' + seconds.toString().padStart(2, '0')

    GET recommendations():
        RETURN preview?.recommendations OR []

    // ============= METHODS =============
    METHOD init():
        isCollapsed = initialCollapsed
        // Expand first section by default
        IF preview?.sections?.length > 0:
            expandedSections = [0]

    METHOD toggleCollapse():
        isCollapsed = NOT isCollapsed
        EMIT 'collapse-changed' WITH isCollapsed

    METHOD toggleSection(index):
        IF index IN expandedSections:
            expandedSections = expandedSections.filter(i => i != index)
        ELSE:
            expandedSections.push(index)

    METHOD isSectionExpanded(index):
        RETURN index IN expandedSections

    METHOD expandAll():
        IF type == 'document':
            expandedSections = preview.sections.map((_, i) => i)
        ELSE:
            expandedSections = preview.chapters.map((_, i) => i)

    METHOD collapseAll():
        expandedSections = []

    // ============= RENDER HELPERS =============
    METHOD renderDocumentPreview():
        RETURN {
            title: preview.title,
            wordCount: preview.word_count,
            sections: preview.sections.map(s => ({
                title: s.title,
                content: s.content_preview,
                hasCode: s.has_code,
                hasList: s.has_list
            })),
            estimatedScenes: preview.estimated_scenes,
            estimatedDuration: preview.estimated_duration,
            hasCode: preview.has_code,
            hasList: preview.has_lists,
            recommendations: preview.recommendations
        }

    METHOD renderYouTubePreview():
        RETURN {
            title: preview.title,
            channel: preview.channel,
            thumbnail: preview.thumbnail,
            duration: formatDuration(preview.duration),
            hasTranscript: preview.has_transcript,
            transcriptLanguages: preview.transcript_languages,
            estimatedScenes: preview.estimated_scenes,
            generationEstimate: preview.generation_estimate
        }

    METHOD formatDuration(seconds):
        hours = Math.floor(seconds / 3600)
        minutes = Math.floor((seconds % 3600) / 60)
        secs = seconds % 60

        IF hours > 0:
            RETURN hours + ':' + minutes.toString().padStart(2, '0') + ':' + secs.toString().padStart(2, '0')
        RETURN minutes + ':' + secs.toString().padStart(2, '0')
```

---

### 2.4 VideoModeSelector Component

**Purpose:** Toggle between single video and video set mode

```pseudocode
COMPONENT VideoModeSelector:
    // ============= STATE =============
    STATE:
        mode: 'single'                // 'single' | 'set'
        videoCount: 1                 // Number of videos for set mode

    // ============= PROPS =============
    PROPS:
        initialMode: 'single'
        minVideos: 2
        maxVideos: 10
        suggestedCount: null          // From preview API

    // ============= COMPUTED =============
    GET isSingleMode():
        RETURN mode == 'single'

    GET isSetMode():
        RETURN mode == 'set'

    GET modeDescription():
        IF mode == 'single':
            RETURN 'Create one complete video from all content'
        RETURN 'Split content into ' + videoCount + ' separate videos'

    // ============= METHODS =============
    METHOD init():
        mode = initialMode
        IF suggestedCount:
            videoCount = suggestedCount

    METHOD selectMode(newMode):
        IF newMode == mode:
            RETURN

        mode = newMode

        IF mode == 'set' AND videoCount < minVideos:
            videoCount = minVideos

        EMIT 'mode-changed' WITH mode
        updateGlobalStore()

    METHOD updateVideoCount(count):
        // Clamp to valid range
        count = Math.max(minVideos, Math.min(maxVideos, count))
        videoCount = count
        EMIT 'count-changed' WITH count
        updateGlobalStore()

    METHOD incrementCount():
        IF videoCount < maxVideos:
            updateVideoCount(videoCount + 1)

    METHOD decrementCount():
        IF videoCount > minVideos:
            updateVideoCount(videoCount - 1)

    METHOD updateGlobalStore():
        $store.appState.videoConfig.mode = mode
        $store.appState.videoConfig.videoCount = videoCount
```

---

### 2.5 MultiLanguageSelector Component

**Purpose:** Select multiple target languages with search

```pseudocode
COMPONENT MultiLanguageSelector:
    // ============= STATE =============
    STATE:
        selectedLanguages: ['en']     // Selected language codes
        searchQuery: ''               // Search filter
        languages: []                 // Available languages from API
        isLoading: true
        popularCodes: ['en', 'es', 'fr', 'de', 'pt', 'zh', 'ja']

    // ============= PROPS =============
    PROPS:
        maxSelections: 10
        initialSelection: ['en']

    // ============= COMPUTED =============
    GET filteredLanguages():
        IF NOT searchQuery:
            RETURN languages

        query = searchQuery.toLowerCase()
        RETURN languages.filter(lang =>
            lang.name.toLowerCase().includes(query) OR
            lang.name_local.toLowerCase().includes(query) OR
            lang.code.toLowerCase().includes(query)
        )

    GET popularLanguages():
        RETURN languages.filter(lang => lang.code IN popularCodes)

    GET selectedCount():
        RETURN selectedLanguages.length

    GET canAddMore():
        RETURN selectedCount < maxSelections

    GET selectedLanguageDetails():
        RETURN selectedLanguages.map(code =>
            languages.find(l => l.code == code)
        ).filter(Boolean)

    // ============= METHODS =============
    METHOD init():
        selectedLanguages = initialSelection
        fetchLanguages()

    ASYNC METHOD fetchLanguages():
        isLoading = true
        TRY:
            response = AWAIT fetch('/api/languages')
            data = AWAIT response.json()
            languages = data.languages
        CATCH error:
            console.error('Failed to fetch languages:', error)
            // Fallback to basic list
            languages = getDefaultLanguages()
        FINALLY:
            isLoading = false

    METHOD toggleLanguage(code):
        IF code IN selectedLanguages:
            // Don't allow removing last language
            IF selectedLanguages.length > 1:
                removeLanguage(code)
        ELSE IF canAddMore:
            addLanguage(code)

    METHOD addLanguage(code):
        IF code NOT IN selectedLanguages AND canAddMore:
            selectedLanguages.push(code)
            EMIT 'selection-changed' WITH selectedLanguages
            updateGlobalStore()

    METHOD removeLanguage(code):
        IF selectedLanguages.length > 1:
            selectedLanguages = selectedLanguages.filter(c => c != code)
            EMIT 'selection-changed' WITH selectedLanguages
            updateGlobalStore()

    METHOD isSelected(code):
        RETURN code IN selectedLanguages

    METHOD getLanguageName(code):
        lang = languages.find(l => l.code == code)
        RETURN lang?.name OR code.toUpperCase()

    METHOD getLanguageLocal(code):
        lang = languages.find(l => l.code == code)
        RETURN lang?.name_local OR ''

    METHOD getVoiceCount(code):
        lang = languages.find(l => l.code == code)
        RETURN lang?.voice_count OR 0

    METHOD clearSearch():
        searchQuery = ''

    METHOD selectAll():
        // Select all visible (filtered) languages up to max
        FOR lang IN filteredLanguages:
            IF selectedLanguages.length >= maxSelections:
                BREAK
            IF lang.code NOT IN selectedLanguages:
                selectedLanguages.push(lang.code)
        EMIT 'selection-changed' WITH selectedLanguages

    METHOD updateGlobalStore():
        $store.appState.videoConfig.targetLanguages = selectedLanguages

    METHOD getDefaultLanguages():
        RETURN [
            {code: 'en', name: 'English', name_local: 'English', voice_count: 4},
            {code: 'es', name: 'Spanish', name_local: 'Espanol', voice_count: 3},
            {code: 'fr', name: 'French', name_local: 'Francais', voice_count: 3},
            {code: 'de', name: 'German', name_local: 'Deutsch', voice_count: 3}
        ]
```

---

### 2.6 MultiVoiceSelector Component

**Purpose:** Select multiple voices per language

```pseudocode
COMPONENT MultiVoiceSelector:
    // ============= STATE =============
    STATE:
        voicesByLanguage: {}          // {langCode: [voiceIds]}
        availableVoices: {}           // {langCode: [voiceObjects]}
        loadingLanguages: []          // Languages being fetched
        audioPreview: null            // Current preview audio element

    // ============= PROPS =============
    PROPS:
        selectedLanguages: []         // From MultiLanguageSelector
        minVoicesPerLang: 1
        maxVoicesPerLang: 4

    // ============= COMPUTED =============
    GET allVoicesSelected():
        FOR lang IN selectedLanguages:
            IF (voicesByLanguage[lang] OR []).length == 0:
                RETURN false
        RETURN true

    GET totalVoiceCount():
        total = 0
        FOR lang IN selectedLanguages:
            total += (voicesByLanguage[lang] OR []).length
        RETURN total

    // ============= METHODS =============
    METHOD init():
        // Initialize voice selections for each language
        FOR lang IN selectedLanguages:
            IF NOT voicesByLanguage[lang]:
                voicesByLanguage[lang] = []
            fetchVoicesForLanguage(lang)

    METHOD $watch('selectedLanguages'):
        // When languages change, fetch voices for new languages
        FOR lang IN selectedLanguages:
            IF lang NOT IN availableVoices:
                fetchVoicesForLanguage(lang)

        // Remove voice selections for removed languages
        FOR lang IN Object.keys(voicesByLanguage):
            IF lang NOT IN selectedLanguages:
                DELETE voicesByLanguage[lang]

    ASYNC METHOD fetchVoicesForLanguage(langCode):
        IF langCode IN loadingLanguages:
            RETURN

        loadingLanguages.push(langCode)

        TRY:
            response = AWAIT fetch('/api/languages/' + langCode + '/voices')
            data = AWAIT response.json()
            availableVoices[langCode] = data.voices

            // Auto-select first voice if none selected
            IF (voicesByLanguage[langCode] OR []).length == 0:
                IF data.voices.length > 0:
                    voicesByLanguage[langCode] = [data.voices[0].id]
        CATCH error:
            console.error('Failed to fetch voices for ' + langCode, error)
            availableVoices[langCode] = getDefaultVoices(langCode)
        FINALLY:
            loadingLanguages = loadingLanguages.filter(l => l != langCode)

    METHOD toggleVoice(langCode, voiceId):
        voices = voicesByLanguage[langCode] OR []

        IF voiceId IN voices:
            // Don't allow removing last voice
            IF voices.length > minVoicesPerLang:
                voicesByLanguage[langCode] = voices.filter(v => v != voiceId)
        ELSE IF voices.length < maxVoicesPerLang:
            voicesByLanguage[langCode] = [...voices, voiceId]

        EMIT 'voices-changed' WITH {lang: langCode, voices: voicesByLanguage[langCode]}
        updateGlobalStore()

    METHOD isVoiceSelected(langCode, voiceId):
        RETURN voiceId IN (voicesByLanguage[langCode] OR [])

    METHOD getSelectedVoiceCount(langCode):
        RETURN (voicesByLanguage[langCode] OR []).length

    METHOD getVoiceName(langCode, voiceId):
        voices = availableVoices[langCode] OR []
        voice = voices.find(v => v.id == voiceId)
        RETURN voice?.name OR voiceId

    METHOD getVoiceDescription(langCode, voiceId):
        voices = availableVoices[langCode] OR []
        voice = voices.find(v => v.id == voiceId)
        RETURN voice?.description OR ''

    ASYNC METHOD previewVoice(langCode, voiceId):
        // Stop any existing preview
        IF audioPreview:
            audioPreview.pause()
            audioPreview = null

        EMIT 'preview-voice' WITH {lang: langCode, voice: voiceId}

        TRY:
            // Generate preview audio
            response = AWAIT fetch('/api/voice-preview', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    language: langCode,
                    voice: voiceId,
                    text: 'This is a sample of the ' + getVoiceName(langCode, voiceId) + ' voice.'
                })
            })

            IF response.ok:
                blob = AWAIT response.blob()
                audioPreview = NEW Audio(URL.createObjectURL(blob))
                audioPreview.play()
        CATCH error:
            console.error('Voice preview failed:', error)

    METHOD stopPreview():
        IF audioPreview:
            audioPreview.pause()
            audioPreview = null

    METHOD updateGlobalStore():
        $store.appState.videoConfig.languageVoices = voicesByLanguage

    METHOD getDefaultVoices(langCode):
        // Fallback voice options
        RETURN [
            {id: 'male', name: 'Male Voice', description: 'Professional male voice'},
            {id: 'female', name: 'Female Voice', description: 'Clear female voice'}
        ]
```

---

### 2.7 ProgressIndicator Component

**Purpose:** Display multi-stage generation progress

```pseudocode
COMPONENT ProgressIndicator:
    // ============= STATE =============
    STATE:
        currentStage: null            // Current stage ID
        progress: 0                   // Overall progress 0-100
        stageProgress: 0              // Progress within current stage
        statusMessage: ''             // Current status message
        stages: []                    // Stage definitions
        eventSource: null             // SSE connection
        isComplete: false
        hasError: false
        errorMessage: null
        startTime: null
        elapsedTime: 0
        estimatedRemaining: null

    // ============= PROPS =============
    PROPS:
        taskId: string
        autoStart: true

    // ============= COMPUTED =============
    GET currentStageIndex():
        RETURN stages.findIndex(s => s.id == currentStage)

    GET completedStages():
        RETURN stages.filter(s => s.status == 'complete')

    GET pendingStages():
        RETURN stages.filter(s => s.status == 'pending')

    GET progressPercent():
        RETURN Math.round(progress)

    GET formattedElapsed():
        minutes = Math.floor(elapsedTime / 60)
        seconds = elapsedTime % 60
        RETURN minutes + ':' + seconds.toString().padStart(2, '0')

    GET formattedRemaining():
        IF NOT estimatedRemaining:
            RETURN 'Calculating...'
        minutes = Math.floor(estimatedRemaining / 60)
        seconds = Math.round(estimatedRemaining % 60)
        RETURN '~' + minutes + ':' + seconds.toString().padStart(2, '0')

    // ============= METHODS =============
    METHOD init():
        // Define stages
        stages = [
            {id: 'parsing', label: 'Parsing Content', status: 'pending', icon: '📄'},
            {id: 'generating', label: 'Generating Scenes', status: 'pending', icon: '🎬'},
            {id: 'audio', label: 'Creating Audio', status: 'pending', icon: '🔊'},
            {id: 'rendering', label: 'Rendering Video', status: 'pending', icon: '🎥'},
            {id: 'finalizing', label: 'Finalizing', status: 'pending', icon: '✨'},
            {id: 'complete', label: 'Complete', status: 'pending', icon: '✅'}
        ]

        IF autoStart AND taskId:
            startMonitoring()

    METHOD startMonitoring():
        startTime = Date.now()
        updateElapsedTime()
        connectSSE()

    METHOD connectSSE():
        eventSource = NEW EventSource('/api/tasks/' + taskId + '/stream')

        eventSource.onmessage = (event) =>
            data = JSON.parse(event.data)
            handleProgressUpdate(data)

        eventSource.onerror = (error) =>
            IF NOT isComplete:
                // Fall back to polling
                disconnectSSE()
                startPolling()

    METHOD disconnectSSE():
        IF eventSource:
            eventSource.close()
            eventSource = null

    METHOD startPolling():
        pollInterval = setInterval(() =>
            fetchProgress()
        , 2000)

    ASYNC METHOD fetchProgress():
        TRY:
            response = AWAIT fetch('/api/tasks/' + taskId)
            data = AWAIT response.json()
            handleProgressUpdate(data)
        CATCH error:
            console.error('Polling failed:', error)

    METHOD handleProgressUpdate(data):
        // Update progress
        progress = data.progress OR 0
        statusMessage = data.message OR ''

        // Update current stage
        IF data.stage:
            updateStage(data.stage, data.stage_progress OR 0)

        // Check for completion
        IF data.status == 'complete':
            completeGeneration(data)
        ELSE IF data.status == 'failed':
            failGeneration(data.error OR 'Generation failed')

        // Update time estimate
        updateTimeEstimate()

    METHOD updateStage(stageId, stageProgress):
        // Mark previous stages as complete
        FOR stage IN stages:
            IF stage.id == stageId:
                stage.status = 'active'
                break
            ELSE IF stage.status != 'complete':
                stage.status = 'complete'

        currentStage = stageId
        this.stageProgress = stageProgress

    METHOD updateElapsedTime():
        IF NOT startTime OR isComplete:
            RETURN

        elapsedTime = Math.floor((Date.now() - startTime) / 1000)

        // Schedule next update
        setTimeout(() => updateElapsedTime(), 1000)

    METHOD updateTimeEstimate():
        IF progress > 10 AND progress < 100:
            elapsed = (Date.now() - startTime) / 1000
            estimatedTotal = elapsed / (progress / 100)
            estimatedRemaining = estimatedTotal - elapsed

    METHOD completeGeneration(data):
        isComplete = true
        progress = 100
        currentStage = 'complete'

        // Mark all stages complete
        FOR stage IN stages:
            stage.status = 'complete'

        disconnectSSE()

        EMIT 'complete' WITH {
            taskId: taskId,
            videoUrl: data.video_url,
            duration: elapsedTime
        }

    METHOD failGeneration(error):
        hasError = true
        errorMessage = error
        disconnectSSE()

        EMIT 'error' WITH {
            taskId: taskId,
            error: error
        }

    METHOD cancelGeneration():
        IF confirm('Are you sure you want to cancel?'):
            fetch('/api/tasks/' + taskId + '/cancel', {method: 'POST'})
            disconnectSSE()
            EMIT 'cancelled' WITH {taskId: taskId}

    METHOD retry():
        hasError = false
        errorMessage = null
        progress = 0

        FOR stage IN stages:
            stage.status = 'pending'

        EMIT 'retry' WITH {taskId: taskId}

    METHOD getStageClass(stage):
        SWITCH stage.status:
            CASE 'complete': RETURN 'text-green-600'
            CASE 'active': RETURN 'text-blue-600 font-semibold'
            CASE 'error': RETURN 'text-red-600'
            DEFAULT: RETURN 'text-gray-400'

    METHOD getStageIndicator(stage):
        SWITCH stage.status:
            CASE 'complete': RETURN '✓'
            CASE 'active': RETURN '●'
            CASE 'error': RETURN '✗'
            DEFAULT: RETURN '○'
```

---

## 3. Integration Points

### 3.1 Global Store Integration

```pseudocode
// app-state.js additions
Alpine.store('appState', {
    // ... existing state ...

    // New modernization state
    dragDrop: {
        file: null,
        preview: null,
        validationStatus: 'idle'
    },

    videoMode: {
        mode: 'single',
        videoCount: 1
    },

    languages: {
        selected: ['en'],
        voicesByLanguage: {'en': ['en-US-JennyNeural']}
    },

    generation: {
        taskId: null,
        progress: 0,
        stage: null,
        isComplete: false
    }
})
```

### 3.2 API Client

```pseudocode
// api-client.js
CONST API = {
    // Document APIs
    ASYNC validateDocument(file):
        formData = NEW FormData()
        formData.append('file', file)
        response = AWAIT fetch('/api/validate/document', {
            method: 'POST',
            body: formData
        })
        RETURN response.json()

    ASYNC previewDocument(file):
        formData = NEW FormData()
        formData.append('file', file)
        response = AWAIT fetch('/api/preview/document', {
            method: 'POST',
            body: formData
        })
        RETURN response.json()

    // YouTube APIs
    ASYNC validateYouTube(url):
        response = AWAIT fetch('/api/youtube/validate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        })
        RETURN response.json()

    ASYNC previewYouTube(url, includeTranscript = false):
        response = AWAIT fetch('/api/youtube/preview', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url, include_transcript_preview: includeTranscript})
        })
        RETURN response.json()

    // Language APIs
    ASYNC getLanguages():
        response = AWAIT fetch('/api/languages')
        RETURN response.json()

    ASYNC getLanguageVoices(langCode):
        response = AWAIT fetch('/api/languages/' + langCode + '/voices')
        RETURN response.json()

    // Generation APIs
    ASYNC generate(config):
        response = AWAIT fetch('/api/parse/' + config.type, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        })
        RETURN response.json()

    ASYNC getTaskStatus(taskId):
        response = AWAIT fetch('/api/tasks/' + taskId)
        RETURN response.json()

    streamTaskProgress(taskId, onUpdate):
        eventSource = NEW EventSource('/api/tasks/' + taskId + '/stream')
        eventSource.onmessage = (e) => onUpdate(JSON.parse(e.data))
        RETURN eventSource
}
```

---

## 4. Event Flow Diagrams

### 4.1 File Upload Event Flow

```
User Action              Component Events              Store Updates
-----------              ----------------              -------------
Drag file         ->     DragDropZone.handleDragEnter
                         dragActive = true

Drop file         ->     DragDropZone.handleDrop
                         DragDropZone.processFile
                         |
                         +-> Read file content
                         +-> API: /api/validate/document
                         +-> EMIT 'file-ready'       ->  $store.dragDrop.file
                         +-> API: /api/preview/document
                         +-> EMIT 'preview-ready'    ->  $store.dragDrop.preview
```

### 4.2 Generation Event Flow

```
User Action              Component Events              Store Updates
-----------              ----------------              -------------
Click Generate    ->     API: /api/parse/{type}
                         |
                         +-> Receive task_id          ->  $store.generation.taskId
                         +-> ProgressIndicator.start
                         |
SSE Event         ->     ProgressIndicator.handleProgressUpdate
                         |
                         +-> Update stage            ->  $store.generation.stage
                         +-> Update progress         ->  $store.generation.progress
                         |
Completion        ->     EMIT 'complete'             ->  $store.generation.isComplete
                         Navigate to /progress#{taskId}
```

---

## 5. Error Handling Patterns

```pseudocode
// Error boundary pattern
FUNCTION withErrorBoundary(asyncFn):
    TRY:
        result = AWAIT asyncFn()
        RETURN {success: true, data: result}
    CATCH error:
        // Log error
        console.error('Operation failed:', error)

        // Show user feedback
        window.dispatchEvent(NEW CustomEvent('show-message', {
            detail: {
                message: error.userMessage OR 'An error occurred',
                type: 'error',
                suggestion: error.suggestion
            }
        }))

        // Report to analytics
        IF window.analytics:
            window.analytics.track('error', {
                operation: asyncFn.name,
                error: error.message
            })

        RETURN {success: false, error: error}

// Usage
result = AWAIT withErrorBoundary(() => API.validateDocument(file))
IF result.success:
    preview = result.data
ELSE:
    // Error already handled
```

---

**Document Version:** 1.0.0
**Last Updated:** November 22, 2025
**Next Phase:** Architecture (FRONTEND_ARCHITECTURE.md)
