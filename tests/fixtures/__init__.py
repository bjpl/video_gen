"""
Test Fixtures Package
=====================

Provides reusable test data and fixtures for integration and E2E testing.
"""

from tests.fixtures.test_data import (
    SAMPLE_DOCUMENTS,
    SAMPLE_YOUTUBE_URLS,
    MOCK_API_RESPONSES,
    TEST_LANGUAGE_CONFIGS,
    TEST_VOICE_CONFIGS,
    get_sample_document,
    get_mock_validation_response,
    get_mock_preview_response,
    get_mock_progress_response,
)

__all__ = [
    'SAMPLE_DOCUMENTS',
    'SAMPLE_YOUTUBE_URLS',
    'MOCK_API_RESPONSES',
    'TEST_LANGUAGE_CONFIGS',
    'TEST_VOICE_CONFIGS',
    'get_sample_document',
    'get_mock_validation_response',
    'get_mock_preview_response',
    'get_mock_progress_response',
]
