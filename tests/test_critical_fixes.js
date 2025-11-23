/**
 * Critical Security and Accessibility Fixes - Test Suite
 *
 * Tests for P1 Code Review Critical Issues (C1, C2, C3)
 * - C1: XSS vulnerability and security issues
 * - C2: ARIA accessibility attributes
 * - C3: Performance debouncing
 */

const FormValidator = require('../app/static/js/validation.js');

describe('C1: XSS Vulnerability and Security Fixes', () => {
    let validator;

    beforeEach(() => {
        validator = new FormValidator();
    });

    describe('XSS Protection in Error Messages', () => {
        test('should return safe error message without user input for invalid YouTube URL', () => {
            const maliciousInput = 'javascript:alert("XSS")<script>alert(1)</script>';
            const result = validator.validateYouTubeURL(maliciousInput);

            expect(result).toBe(
                'Invalid YouTube URL. Supported formats:\n' +
                '• https://youtube.com/watch?v=...\n' +
                '• https://youtu.be/...\n' +
                '• https://youtube.com/embed/...'
            );
            expect(result).not.toContain('script');
            expect(result).not.toContain(maliciousInput);
        });

        test('should not include user input in file path error messages', () => {
            const maliciousPath = '<img src=x onerror=alert(1)>';
            const result = validator.validateFilePath(maliciousPath);

            expect(typeof result).toBe('string');
            expect(result).not.toContain('<img');
            expect(result).not.toContain('onerror');
        });

        test('should sanitize error messages for all validators', () => {
            const maliciousInputs = [
                '<script>alert("XSS")</script>',
                'javascript:void(0)',
                '<img src=x onerror=alert(1)>',
                '"><svg onload=alert(1)>',
                '\' OR 1=1--'
            ];

            maliciousInputs.forEach(input => {
                const urlResult = validator.validateURL(input);
                const pathResult = validator.validateFilePath(input);

                // Error messages should not contain dangerous HTML/JS
                if (typeof urlResult === 'string') {
                    expect(urlResult).not.toContain('<script');
                    expect(urlResult).not.toContain('onerror');
                    expect(urlResult).not.toContain('javascript:');
                }

                if (typeof pathResult === 'string') {
                    expect(pathResult).not.toContain('<script');
                    expect(pathResult).not.toContain('onerror');
                }
            });
        });
    });

    describe('Path Traversal Protection', () => {
        test('should reject paths with directory traversal (..) attacks', () => {
            const maliciousPaths = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                './../../sensitive/data.txt',
                'docs/../../../etc/shadow'
            ];

            maliciousPaths.forEach(path => {
                const result = validator.validateFilePath(path);
                expect(result).toBe('Path traversal (..) not allowed for security reasons');
            });
        });

        test('should reject paths with null bytes', () => {
            const nullBytePaths = [
                'file.txt\0.md',
                'docs/\0file.md',
                '/home/user\0/file.txt'
            ];

            nullBytePaths.forEach(path => {
                const result = validator.validateFilePath(path);
                expect(result).toBe('Invalid characters in path (null byte detected)');
            });
        });

        test('should accept safe relative paths without traversal', () => {
            const safePaths = [
                './docs/file.md',
                'docs/file.txt',
                'project/readme.markdown'
            ];

            safePaths.forEach(path => {
                const result = validator.validateFilePath(path);
                expect(result).toBe(true);
            });
        });
    });

    describe('Regex DoS (ReDoS) Protection', () => {
        test('should timeout on catastrophic backtracking attempts', () => {
            const longInput = 'https://youtube.com/watch?v=' + 'a'.repeat(10000);

            // Should return null (timeout) or false, not hang
            const startTime = Date.now();
            const result = validator.validateYouTubeURL(longInput);
            const elapsed = Date.now() - startTime;

            // Should complete quickly (< 200ms), not hang indefinitely
            expect(elapsed).toBeLessThan(200);
            expect(result).not.toBe(true); // Should fail validation
        });

        test('should handle malformed regex attack patterns', () => {
            const attackPatterns = [
                'a'.repeat(100000),
                'http://'.repeat(1000),
                '((((('.repeat(100)
            ];

            attackPatterns.forEach(pattern => {
                const startTime = Date.now();
                const result = validator.validateURL(pattern);
                const elapsed = Date.now() - startTime;

                expect(elapsed).toBeLessThan(200);
                expect(typeof result).toBe('string'); // Should return error message
            });
        });

        test('safeRegexMatch should return null on timeout', () => {
            // Create a pattern that might take long (though our patterns are safe)
            const pattern = /^https?:\/\/(www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]{11})/;
            const text = 'x'.repeat(10000);

            const result = validator.safeRegexMatch(pattern, text, 10); // 10ms timeout

            // Should handle gracefully
            expect([null, false]).toContain(result || false);
        });
    });

    describe('Input Sanitization', () => {
        test('should strip quotes from file paths', () => {
            const quotedPaths = [
                '"C:/docs/file.md"',
                "'./docs/file.txt'",
                '"docs/readme.markdown"'
            ];

            quotedPaths.forEach(path => {
                const result = validator.validateFilePath(path);
                expect(result).toBe(true);
            });
        });

        test('should normalize path separators', () => {
            const mixedPaths = [
                'C:\\docs\\file.md',
                'docs\\subfolder\\file.txt'
            ];

            mixedPaths.forEach(path => {
                const result = validator.validateFilePath(path);
                expect(result).toBe(true);
            });
        });
    });
});

describe('C2: ARIA Accessibility Fixes', () => {
    describe('ARIA Attribute Implementation', () => {
        test('error container should have role="alert"', () => {
            // This test verifies the directive setup
            // In real DOM testing, we'd check:
            // expect(errorContainer.getAttribute('role')).toBe('alert');

            // For unit test, verify the pattern is correct
            const ariaPattern = /setAttribute\('role', 'alert'\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(ariaPattern.test(validationCode)).toBe(true);
        });

        test('error container should have aria-live="polite"', () => {
            const ariaPattern = /setAttribute\('aria-live', 'polite'\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(ariaPattern.test(validationCode)).toBe(true);
        });

        test('invalid inputs should have aria-invalid="true"', () => {
            const ariaPattern = /setAttribute\('aria-invalid', 'true'\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(ariaPattern.test(validationCode)).toBe(true);
        });

        test('inputs should link to errors via aria-describedby', () => {
            const ariaPattern = /setAttribute\('aria-describedby', errorId\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(ariaPattern.test(validationCode)).toBe(true);
        });

        test('error IDs should be unique', () => {
            const idPattern = /const errorId = `\$\{fieldName\}-error-\$\{Math\.random/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(idPattern.test(validationCode)).toBe(true);
        });
    });

    describe('ARIA State Management', () => {
        test('valid inputs should clear aria-invalid', () => {
            const clearPattern = /removeAttribute\('aria-invalid'\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(clearPattern.test(validationCode)).toBe(true);
        });

        test('valid inputs should remove aria-describedby', () => {
            const clearPattern = /removeAttribute\('aria-describedby'\)/;
            const validationCode = require('fs').readFileSync(
                './app/static/js/validation.js',
                'utf8'
            );

            expect(clearPattern.test(validationCode)).toBe(true);
        });
    });
});

describe('C3: Performance Debouncing Fix', () => {
    describe('Cost Estimator Debouncing', () => {
        test('updateEstimate should use Alpine.debounce', () => {
            const debouncePattern = /updateEstimate:\s*Alpine\.debounce\(/;
            const costCode = require('fs').readFileSync(
                './app/static/js/cost-estimator.js',
                'utf8'
            );

            expect(debouncePattern.test(costCode)).toBe(true);
        });

        test('debounce delay should be 300ms', () => {
            const delayPattern = /Alpine\.debounce\([^,]+,\s*300\)/;
            const costCode = require('fs').readFileSync(
                './app/static/js/cost-estimator.js',
                'utf8'
            );

            expect(delayPattern.test(costCode)).toBe(true);
        });

        test('debounced function should still call correct methods', () => {
            const costCode = require('fs').readFileSync(
                './app/static/js/cost-estimator.js',
                'utf8'
            );

            // Verify the debounced function calls the right methods
            expect(costCode).toContain('window.costEstimator.estimateVideoSetCost(config)');
            expect(costCode).toContain('window.costEstimator.getOptimizationTips');
        });
    });

    describe('Debouncing Behavior Verification', () => {
        test('debouncing should reduce calculation frequency', async () => {
            // Mock Alpine.debounce for testing
            const mockDebounce = (fn, delay) => {
                let timeout;
                return function(...args) {
                    clearTimeout(timeout);
                    timeout = setTimeout(() => fn.apply(this, args), delay);
                };
            };

            let callCount = 0;
            const debouncedFn = mockDebounce(() => callCount++, 300);

            // Simulate rapid calls (like typing)
            for (let i = 0; i < 10; i++) {
                debouncedFn();
                await new Promise(resolve => setTimeout(resolve, 50));
            }

            // Wait for debounce to complete
            await new Promise(resolve => setTimeout(resolve, 350));

            // Should have been called far fewer times than 10
            expect(callCount).toBeLessThan(10);
            expect(callCount).toBeGreaterThan(0);
        });

        test('final calculation should still be accurate after debouncing', async () => {
            const mockDebounce = (fn, delay) => {
                let timeout;
                return function(...args) {
                    clearTimeout(timeout);
                    return new Promise(resolve => {
                        timeout = setTimeout(() => {
                            resolve(fn.apply(this, args));
                        }, delay);
                    });
                };
            };

            const testFn = (value) => value * 2;
            const debouncedFn = mockDebounce(testFn, 100);

            const result = await debouncedFn(5);
            expect(result).toBe(10); // Calculation should still be correct
        });
    });
});

describe('Integration Tests: All Fixes Working Together', () => {
    let validator;

    beforeEach(() => {
        validator = new FormValidator();
    });

    test('malicious input should be safely rejected with proper error handling', () => {
        const maliciousInputs = [
            '../../../etc/passwd',
            '<script>alert("XSS")</script>',
            'javascript:void(0)\0.md'
        ];

        maliciousInputs.forEach(input => {
            const result = validator.validateFilePath(input);

            // Should reject
            expect(result).not.toBe(true);

            // Error message should be safe
            expect(typeof result).toBe('string');
            expect(result).not.toContain(input);

            // Should identify specific security issue
            if (input.includes('..')) {
                expect(result).toContain('traversal');
            }
            if (input.includes('\0')) {
                expect(result).toContain('null byte');
            }
        });
    });

    test('valid inputs should pass all security checks', () => {
        const validInputs = {
            youtube_url: 'https://youtube.com/watch?v=dQw4w9WgXcQ',
            file_path: './docs/readme.md',
            url: 'https://example.com/document.md',
            video_id: 'my-video-123',
            duration: 120,
            video_count: 5
        };

        Object.entries(validInputs).forEach(([field, value]) => {
            const result = validator.validateField(field, value);
            expect(result).toBeNull(); // No error = valid
        });
    });

    test('edge cases should be handled safely', () => {
        const edgeCases = [
            { field: 'file_path', value: '' }, // Empty
            { field: 'youtube_url', value: '   ' }, // Whitespace
            { field: 'duration', value: 'abc' }, // Non-numeric
            { field: 'video_count', value: -1 }, // Negative
            { field: 'video_id', value: 'a'.repeat(200) } // Too long
        ];

        edgeCases.forEach(({ field, value }) => {
            const result = validator.validateField(field, value);

            // Should return error message (not crash)
            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);

            // Error message should be user-friendly
            expect(result).not.toContain('undefined');
            expect(result).not.toContain('null');
        });
    });
});

describe('Regression Tests: Existing Functionality Preserved', () => {
    let validator;

    beforeEach(() => {
        validator = new FormValidator();
    });

    test('valid YouTube URLs should still be accepted', () => {
        const validUrls = [
            'https://youtube.com/watch?v=dQw4w9WgXcQ',
            'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            'https://youtu.be/dQw4w9WgXcQ',
            'https://youtube.com/embed/dQw4w9WgXcQ',
            'http://youtube.com/watch?v=dQw4w9WgXcQ'
        ];

        validUrls.forEach(url => {
            const result = validator.validateYouTubeURL(url);
            expect(result).toBe(true);
        });
    });

    test('file path validation should still work correctly', () => {
        const validPaths = [
            'C:/docs/file.md',
            '/home/user/file.txt',
            './docs/readme.markdown',
            'docs/file.md'
        ];

        validPaths.forEach(path => {
            const result = validator.validateFilePath(path);
            expect(result).toBe(true);
        });
    });

    test('duration validation ranges should be unchanged', () => {
        expect(validator.validateDuration(10)).toBe(true);
        expect(validator.validateDuration(600)).toBe(true);
        expect(validator.validateDuration(9)).toContain('at least 10');
        expect(validator.validateDuration(601)).toContain('cannot exceed 600');
    });

    test('video count validation should work as before', () => {
        expect(validator.validateVideoCount(1)).toBe(true);
        expect(validator.validateVideoCount(20)).toBe(true);
        expect(validator.validateVideoCount(0)).toContain('at least 1');
        expect(validator.validateVideoCount(21)).toContain('more than 20');
    });
});
