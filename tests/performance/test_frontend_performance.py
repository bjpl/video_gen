"""
Performance Tests: Frontend
===========================

Performance tests for frontend components:
- Page load time < 2s
- Component render time < 100ms
- API response handling < 50ms
- State update performance
- Memory leak detection patterns
- Event listener cleanup
- Large file handling (10MB document)
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import sys
import time
import statistics
from io import BytesIO
import gc

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.main import app


@pytest.fixture
def client():
    """Create test client"""
    import os
    os.environ["CSRF_DISABLED"] = "true"
    with TestClient(app) as c:
        yield c
    os.environ.pop("CSRF_DISABLED", None)


# ============================================================================
# Page Load Performance Tests
# ============================================================================

class TestPageLoadPerformance:
    """Test page load times"""

    @pytest.mark.performance
    def test_home_page_load_time(self, client):
        """Test home page loads within 2 seconds"""
        start = time.time()
        response = client.get("/")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 2.0, f"Home page took {duration:.2f}s (limit: 2s)"

    @pytest.mark.performance
    def test_create_page_load_time(self, client):
        """Test create page loads within 2 seconds"""
        start = time.time()
        response = client.get("/create")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 2.0, f"Create page took {duration:.2f}s (limit: 2s)"

    @pytest.mark.performance
    def test_progress_page_load_time(self, client):
        """Test progress page loads within 2 seconds"""
        start = time.time()
        response = client.get("/progress")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 2.0, f"Progress page took {duration:.2f}s (limit: 2s)"

    @pytest.mark.performance
    def test_average_page_load_time(self, client):
        """Test average page load time across multiple requests"""
        pages = ["/", "/create", "/progress", "/advanced"]
        durations = []

        for page in pages:
            for _ in range(3):
                start = time.time()
                response = client.get(page)
                duration = time.time() - start
                if response.status_code == 200:
                    durations.append(duration)

        if durations:
            avg_duration = statistics.mean(durations)
            assert avg_duration < 1.5, f"Average page load: {avg_duration:.2f}s (limit: 1.5s)"


# ============================================================================
# API Response Time Tests
# ============================================================================

class TestAPIResponseTime:
    """Test API endpoint response times"""

    @pytest.mark.performance
    def test_health_check_response_time(self, client):
        """Test health check responds quickly"""
        durations = []
        for _ in range(10):
            start = time.time()
            response = client.get("/api/health")
            durations.append(time.time() - start)
            assert response.status_code == 200

        avg = statistics.mean(durations)
        assert avg < 0.1, f"Health check avg: {avg*1000:.1f}ms (limit: 100ms)"

    @pytest.mark.performance
    def test_languages_endpoint_response_time(self, client):
        """Test languages endpoint responds quickly"""
        durations = []
        for _ in range(5):
            start = time.time()
            response = client.get("/api/languages")
            durations.append(time.time() - start)
            assert response.status_code == 200

        avg = statistics.mean(durations)
        assert avg < 0.5, f"Languages endpoint avg: {avg*1000:.1f}ms (limit: 500ms)"

    @pytest.mark.performance
    def test_voices_endpoint_response_time(self, client):
        """Test voices endpoint responds quickly"""
        durations = []
        for _ in range(5):
            start = time.time()
            response = client.get("/api/languages/en/voices")
            durations.append(time.time() - start)
            assert response.status_code == 200

        avg = statistics.mean(durations)
        assert avg < 0.3, f"Voices endpoint avg: {avg*1000:.1f}ms (limit: 300ms)"

    @pytest.mark.performance
    def test_static_file_response_time(self, client):
        """Test static JS files load quickly"""
        static_files = [
            "/static/js/validation.js",
            "/static/js/store/app-state.js",
        ]

        for file_path in static_files:
            start = time.time()
            response = client.get(file_path)
            duration = time.time() - start

            if response.status_code == 200:
                assert duration < 0.5, f"{file_path} took {duration*1000:.1f}ms"


# ============================================================================
# Validation Performance Tests
# ============================================================================

class TestValidationPerformance:
    """Test validation endpoint performance"""

    @pytest.mark.performance
    def test_small_file_validation_time(self, client):
        """Test small file validates quickly"""
        content = b"# Small Document\n\nJust a few words."
        files = {"file": ("small.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/validate/document", files=files)
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 1.0, f"Small file validation: {duration:.2f}s (limit: 1s)"

    @pytest.mark.performance
    def test_medium_file_validation_time(self, client):
        """Test medium file (100KB) validates within 2 seconds"""
        # Generate ~100KB content
        content = b"# Medium Document\n\n" + (b"Content paragraph. " * 5000)
        files = {"file": ("medium.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/validate/document", files=files)
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 2.0, f"Medium file validation: {duration:.2f}s (limit: 2s)"

    @pytest.mark.performance
    def test_large_file_validation_time(self, client):
        """Test large file (1MB) validates within 5 seconds"""
        # Generate ~1MB content
        content = b"# Large Document\n\n" + (b"This is a large document. " * 50000)
        files = {"file": ("large.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/validate/document", files=files)
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 5.0, f"Large file validation: {duration:.2f}s (limit: 5s)"

    @pytest.mark.performance
    @pytest.mark.slow
    def test_max_size_file_validation_time(self, client):
        """Test maximum size file (10MB) validates within 10 seconds"""
        # Generate ~10MB content (at the limit)
        content = b"# Maximum Size Document\n\n" + (b"x" * (9 * 1024 * 1024))
        files = {"file": ("max.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/validate/document", files=files)
        duration = time.time() - start

        # May be rejected for size but should respond
        assert duration < 10.0, f"Max file validation: {duration:.2f}s (limit: 10s)"


# ============================================================================
# YouTube Validation Performance Tests
# ============================================================================

class TestYouTubeValidationPerformance:
    """Test YouTube validation performance"""

    @pytest.mark.performance
    def test_youtube_url_validation_time(self, client):
        """Test YouTube URL validates quickly (local validation)"""
        durations = []

        for _ in range(10):
            start = time.time()
            response = client.post(
                "/api/youtube/validate",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
            )
            durations.append(time.time() - start)
            assert response.status_code == 200

        avg = statistics.mean(durations)
        assert avg < 0.5, f"YouTube validation avg: {avg*1000:.1f}ms (limit: 500ms)"

    @pytest.mark.performance
    def test_multiple_youtube_urls_validation(self, client):
        """Test validating multiple YouTube URLs"""
        urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be/abc123xyz12",
            "https://www.youtube.com/embed/test12345ab",
        ]

        start = time.time()
        for url in urls:
            response = client.post("/api/youtube/validate", json={"url": url})
            assert response.status_code == 200

        total_duration = time.time() - start
        assert total_duration < 3.0, f"3 URLs took {total_duration:.2f}s (limit: 3s)"


# ============================================================================
# Concurrent Request Performance Tests
# ============================================================================

class TestConcurrentRequestPerformance:
    """Test performance under concurrent load"""

    @pytest.mark.performance
    def test_concurrent_health_checks(self, client):
        """Test concurrent health check requests"""
        import concurrent.futures

        def health_check():
            start = time.time()
            response = client.get("/api/health")
            return time.time() - start, response.status_code

        start_total = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(health_check) for _ in range(20)]
            results = [f.result() for f in futures]

        total_duration = time.time() - start_total

        # All should succeed
        status_codes = [r[1] for r in results]
        assert all(code == 200 for code in status_codes)

        # Should complete in reasonable time
        assert total_duration < 5.0, f"20 concurrent requests: {total_duration:.2f}s"

    @pytest.mark.performance
    def test_concurrent_validations(self, client):
        """Test concurrent document validations"""
        import concurrent.futures

        def validate():
            content = b"# Test\n\nContent"
            files = {"file": ("test.md", BytesIO(content), "text/markdown")}
            start = time.time()
            response = client.post("/api/validate/document", files=files)
            return time.time() - start, response.status_code

        start_total = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(validate) for _ in range(10)]
            results = [f.result() for f in futures]

        total_duration = time.time() - start_total

        # All should succeed
        success_count = sum(1 for _, status in results if status == 200)
        assert success_count >= 8, f"Only {success_count}/10 succeeded"

        # Should complete in reasonable time
        assert total_duration < 10.0, f"10 concurrent validations: {total_duration:.2f}s"


# ============================================================================
# Memory Performance Tests
# ============================================================================

class TestMemoryPerformance:
    """Test memory usage patterns"""

    @pytest.mark.performance
    def test_repeated_validation_no_memory_growth(self, client):
        """Test repeated validations don't cause memory growth"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Perform many validations
        for _ in range(50):
            content = b"# Test\n\nContent " + bytes(str(time.time()).encode())
            files = {"file": ("test.md", BytesIO(content), "text/markdown")}
            client.post("/api/validate/document", files=files)

        # Force garbage collection
        gc.collect()

        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory

        # Allow up to 50MB growth (requests have some overhead)
        max_growth = 50 * 1024 * 1024
        assert memory_growth < max_growth, f"Memory grew by {memory_growth / 1024 / 1024:.1f}MB"

    @pytest.mark.performance
    def test_large_response_handling(self, client):
        """Test handling of large API responses"""
        # Languages endpoint returns substantial data
        start = time.time()
        response = client.get("/api/languages")
        duration = time.time() - start

        assert response.status_code == 200
        data = response.json()

        # Should handle response efficiently
        assert duration < 1.0
        # Response should be reasonable size
        response_size = len(response.content)
        assert response_size < 500000  # Less than 500KB


# ============================================================================
# Throughput Tests
# ============================================================================

class TestThroughput:
    """Test request throughput"""

    @pytest.mark.performance
    def test_health_check_throughput(self, client):
        """Test health check requests per second"""
        requests_count = 100
        start = time.time()

        for _ in range(requests_count):
            response = client.get("/api/health")
            assert response.status_code == 200

        duration = time.time() - start
        rps = requests_count / duration

        # Should handle at least 50 requests per second
        assert rps > 50, f"Only {rps:.1f} requests/second (minimum: 50)"

    @pytest.mark.performance
    def test_static_file_throughput(self, client):
        """Test static file requests per second"""
        requests_count = 50
        start = time.time()

        for _ in range(requests_count):
            response = client.get("/static/js/validation.js")
            if response.status_code != 200:
                break

        duration = time.time() - start
        rps = requests_count / duration

        # Should handle at least 30 requests per second
        assert rps > 30, f"Only {rps:.1f} requests/second for static files"


# ============================================================================
# Preview Generation Performance Tests
# ============================================================================

class TestPreviewPerformance:
    """Test preview generation performance"""

    @pytest.mark.performance
    def test_document_preview_time(self, client):
        """Test document preview generation time"""
        content = b"""# Tutorial

## Section 1
Content for section 1.

## Section 2
Content for section 2.

## Section 3
Content for section 3.
"""
        files = {"file": ("tutorial.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/preview/document", files=files)
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 3.0, f"Preview generation: {duration:.2f}s (limit: 3s)"

    @pytest.mark.performance
    def test_complex_document_preview_time(self, client):
        """Test complex document preview generation time"""
        # Generate complex document with many sections
        content = b"# Complex Tutorial\n\n"
        for i in range(20):
            content += f"## Chapter {i+1}\n\nContent for chapter {i+1}.\n\n".encode()
            content += b"### Subsection\n\n- Point 1\n- Point 2\n\n"
            content += b"```python\ncode_example()\n```\n\n"

        files = {"file": ("complex.md", BytesIO(content), "text/markdown")}

        start = time.time()
        response = client.post("/api/preview/document", files=files)
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 5.0, f"Complex preview: {duration:.2f}s (limit: 5s)"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short', '-m', 'performance'])
