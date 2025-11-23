/**
 * VoicePreviewPlayer - Utility module for voice preview audio playback
 *
 * Features:
 * - Web Audio API integration for better control
 * - Support for various audio formats
 * - Loading states and error handling
 * - Waveform visualization data
 *
 * @requires Web Audio API support
 */

class VoicePreviewPlayer {
    constructor(options = {}) {
        this.options = {
            onStateChange: options.onStateChange || null,
            onError: options.onError || null,
            onWaveformData: options.onWaveformData || null,
            ...options
        };

        // Audio state
        this.audioContext = null;
        this.source = null;
        this.analyser = null;
        this.audio = null;

        // Playback state
        this.state = 'idle'; // 'idle', 'loading', 'playing', 'paused', 'error'
        this.currentVoice = null;

        // Waveform animation
        this.animationFrame = null;
        this.waveformData = new Uint8Array(32);
    }

    /**
     * Initialize Web Audio API context
     */
    initAudioContext() {
        if (!this.audioContext) {
            try {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                this.audioContext = new AudioContext();
            } catch (error) {
                console.error('[VoicePreviewPlayer] Web Audio API not supported:', error);
                return false;
            }
        }
        return true;
    }

    /**
     * Play audio from URL or blob
     * @param {string|Blob} source - Audio URL or Blob
     * @param {Object} voiceInfo - Voice metadata
     */
    async play(source, voiceInfo = {}) {
        this.stop();

        this.currentVoice = voiceInfo;
        this.setState('loading');

        try {
            let audioUrl = source;

            // Handle Blob source
            if (source instanceof Blob) {
                audioUrl = URL.createObjectURL(source);
            }

            // Create HTML5 Audio element
            this.audio = new Audio();
            this.audio.crossOrigin = 'anonymous';

            // Set up event listeners
            this.audio.addEventListener('canplaythrough', () => {
                this.startPlayback();
            }, { once: true });

            this.audio.addEventListener('ended', () => {
                this.setState('idle');
                this.cleanupWaveform();
            });

            this.audio.addEventListener('error', (e) => {
                this.handleError('Audio playback failed', e);
            });

            this.audio.addEventListener('pause', () => {
                if (this.state !== 'idle') {
                    this.setState('paused');
                }
            });

            // Load audio
            this.audio.src = audioUrl;
            this.audio.load();

        } catch (error) {
            this.handleError('Failed to load audio', error);
        }
    }

    /**
     * Start playback after audio is loaded
     */
    async startPlayback() {
        try {
            // Initialize audio context for waveform
            if (this.initAudioContext() && this.options.onWaveformData) {
                this.setupAnalyser();
            }

            await this.audio.play();
            this.setState('playing');
            this.startWaveformAnimation();

        } catch (error) {
            this.handleError('Playback failed', error);
        }
    }

    /**
     * Setup audio analyser for waveform visualization
     */
    setupAnalyser() {
        if (!this.audioContext || !this.audio) return;

        try {
            // Resume audio context if suspended
            if (this.audioContext.state === 'suspended') {
                this.audioContext.resume();
            }

            // Create analyser node
            this.analyser = this.audioContext.createAnalyser();
            this.analyser.fftSize = 64;
            this.waveformData = new Uint8Array(this.analyser.frequencyBinCount);

            // Create media element source
            this.source = this.audioContext.createMediaElementSource(this.audio);
            this.source.connect(this.analyser);
            this.analyser.connect(this.audioContext.destination);

        } catch (error) {
            // Waveform visualization is optional
            console.warn('[VoicePreviewPlayer] Could not setup analyser:', error);
        }
    }

    /**
     * Start waveform animation loop
     */
    startWaveformAnimation() {
        if (!this.analyser || !this.options.onWaveformData) return;

        const animate = () => {
            if (this.state !== 'playing') return;

            this.analyser.getByteFrequencyData(this.waveformData);
            this.options.onWaveformData(this.waveformData);

            this.animationFrame = requestAnimationFrame(animate);
        };

        animate();
    }

    /**
     * Stop waveform animation
     */
    cleanupWaveform() {
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
            this.animationFrame = null;
        }

        if (this.options.onWaveformData) {
            this.options.onWaveformData(new Uint8Array(32).fill(0));
        }
    }

    /**
     * Stop playback
     */
    stop() {
        this.cleanupWaveform();

        if (this.audio) {
            this.audio.pause();
            this.audio.currentTime = 0;

            // Revoke blob URL if applicable
            if (this.audio.src.startsWith('blob:')) {
                URL.revokeObjectURL(this.audio.src);
            }

            this.audio = null;
        }

        if (this.source) {
            try {
                this.source.disconnect();
            } catch (e) {
                // Ignore disconnect errors
            }
            this.source = null;
        }

        this.currentVoice = null;
        this.setState('idle');
    }

    /**
     * Pause playback
     */
    pause() {
        if (this.audio && this.state === 'playing') {
            this.audio.pause();
            this.setState('paused');
            this.cleanupWaveform();
        }
    }

    /**
     * Resume playback
     */
    async resume() {
        if (this.audio && this.state === 'paused') {
            try {
                await this.audio.play();
                this.setState('playing');
                this.startWaveformAnimation();
            } catch (error) {
                this.handleError('Resume failed', error);
            }
        }
    }

    /**
     * Toggle play/pause
     */
    toggle() {
        if (this.state === 'playing') {
            this.pause();
        } else if (this.state === 'paused') {
            this.resume();
        }
    }

    /**
     * Get current playback state
     */
    getCurrentState() {
        return {
            state: this.state,
            voice: this.currentVoice,
            currentTime: this.audio?.currentTime || 0,
            duration: this.audio?.duration || 0,
            progress: this.audio ? (this.audio.currentTime / this.audio.duration) * 100 : 0
        };
    }

    /**
     * Set state and notify
     */
    setState(newState) {
        const previousState = this.state;
        this.state = newState;

        if (this.options.onStateChange) {
            this.options.onStateChange(newState, previousState, this.currentVoice);
        }
    }

    /**
     * Handle errors
     */
    handleError(message, error) {
        console.error(`[VoicePreviewPlayer] ${message}:`, error);
        this.setState('error');

        if (this.options.onError) {
            this.options.onError(message, error);
        }
    }

    /**
     * Check if audio format is supported
     */
    static isFormatSupported(mimeType) {
        const audio = document.createElement('audio');
        const canPlay = audio.canPlayType(mimeType);
        return canPlay === 'probably' || canPlay === 'maybe';
    }

    /**
     * Get supported audio formats
     */
    static getSupportedFormats() {
        const formats = [
            { mime: 'audio/mpeg', ext: '.mp3', name: 'MP3' },
            { mime: 'audio/ogg', ext: '.ogg', name: 'OGG' },
            { mime: 'audio/wav', ext: '.wav', name: 'WAV' },
            { mime: 'audio/webm', ext: '.webm', name: 'WebM' },
            { mime: 'audio/aac', ext: '.aac', name: 'AAC' }
        ];

        return formats.filter(f => VoicePreviewPlayer.isFormatSupported(f.mime));
    }

    /**
     * Cleanup resources
     */
    destroy() {
        this.stop();

        if (this.audioContext && this.audioContext.state !== 'closed') {
            this.audioContext.close();
        }

        this.audioContext = null;
        this.analyser = null;
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VoicePreviewPlayer;
}

// Make available globally
window.VoicePreviewPlayer = VoicePreviewPlayer;
