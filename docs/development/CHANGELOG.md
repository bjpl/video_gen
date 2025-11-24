# Changelog

All notable changes to the video_gen project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2025-11-22

### Added - Frontend Modernization

#### New Components
- **DragDropZone** (`/app/static/js/components/drag-drop-zone.js`)
  - Visual drag-drop zone with hover effects
  - File type filtering (.md, .txt, .rst, .markdown)
  - Size validation (10MB limit)
  - Real-time validation feedback
  - API integration with `/api/validate/document`
  - Preview generation trigger

- **ValidationFeedback** (`/app/static/js/components/validation-feedback.js`)
  - Debounced input validation (500ms)
  - YouTube URL validation with suggestions
  - Document validation with error recovery hints
  - Visual state indicators (success/error/warning/loading)
  - ARIA accessibility support

#### Enhanced State Management
- **AppState v2.0.0** (`/app/static/js/store/app-state.js`)
  - State versioning for migrations
  - Event bus integration
  - Language and voice management
  - Progress tracking with stages
  - Comprehensive persistence with localStorage
  - Backward compatibility with legacy API

#### Security Enhancements
- **Input Sanitization** (FIX C3)
  - `sanitizeFilename()` - Removes dangerous characters
  - `sanitizeText()` - Null byte removal, length limits
  - `sanitizeForDisplay()` - XSS prevention with textContent
  - `sanitizeUrl()` - Protocol validation, javascript: blocking

- **ReDoS Prevention**
  - `safeRegexMatch()` with 100ms timeout protection

- **Path Traversal Prevention**
  - Blocked `..` in file paths
  - Null byte detection
  - Reserved Windows filename handling

#### Testing
- 143 new frontend tests (all passing)
  - DragDropZone tests (28 tests)
  - Validation tests (49 tests)
  - Preview tests (35 tests)
  - Language selector tests (31 tests)

#### Documentation
- `/docs/frontend/FRONTEND_SPECIFICATION.md`
- `/docs/frontend/FRONTEND_ARCHITECTURE.md`
- `/docs/frontend/COMPONENT_PSEUDOCODE.md`
- `/docs/frontend/CODE_REVIEW_REPORT.md`
- `/docs/frontend/IMPLEMENTATION_SUMMARY.md`
- `/docs/frontend/FINAL_REVIEW_REPORT.md`

### Changed

- Modernized Alpine.js component architecture
- Enhanced `validation.js` with security constants
- Improved error handling and user feedback
- Enhanced accessibility (WCAG AA compliant)
- Mobile-responsive design improvements

### Security

- Added input sanitization helpers
- Fixed potential XSS via textContent usage
- Added safe regex matching with timeout
- Implemented path traversal prevention
- Added filename sanitization for uploads

### Performance

- Debounced validation to reduce API calls
- Optimized state persistence
- Lazy component initialization

---

## [1.0.0] - 2025-11-18

### Added - Initial Production Release

- Core video generation pipeline
- Document parsing (Markdown, RST, TXT)
- YouTube transcript extraction
- AI narration with Claude Sonnet 4.5
- Multi-language support (28+ languages)
- Edge TTS voice synthesis
- Modular renderer system (7 modules)
- Stage-based pipeline (6 stages)
- Web UI with Alpine.js
- REST API endpoints
- CLI interface
- Test suite (475 tests, 79% coverage)

### Infrastructure

- Railway deployment configuration
- Docker containerization
- CI/CD pipeline
- Health check endpoints

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 2.0.0 | 2025-11-22 | Frontend modernization |
| 1.0.0 | 2025-11-18 | Initial production release |

---

*Maintained by the video_gen development team*
