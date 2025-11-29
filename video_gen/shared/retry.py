"""
Retry logic and circuit breaker for transient failures.

Provides decorators and utilities for handling transient failures
in external API calls and other unreliable operations.
"""

import asyncio
import functools
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Callable, Optional, Type, Tuple, TypeVar, Union,
    Awaitable, List
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RetryStrategy(Enum):
    """Retry backoff strategies."""
    FIXED = "fixed"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    EXPONENTIAL_JITTER = "exponential_jitter"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_JITTER
    multiplier: float = 2.0
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    non_retryable_exceptions: Tuple[Type[Exception], ...] = ()

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number."""
        if self.strategy == RetryStrategy.FIXED:
            delay = self.initial_delay
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.initial_delay * attempt
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.initial_delay * (self.multiplier ** (attempt - 1))
        elif self.strategy == RetryStrategy.EXPONENTIAL_JITTER:
            import random
            base_delay = self.initial_delay * (self.multiplier ** (attempt - 1))
            delay = base_delay * (0.5 + random.random())
        else:
            delay = self.initial_delay

        return min(delay, self.max_delay)


def retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_JITTER,
    multiplier: float = 2.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    non_retryable_exceptions: Tuple[Type[Exception], ...] = (),
    on_retry: Optional[Callable[[Exception, int], None]] = None
):
    """Decorator for retrying functions on transient failures.

    Args:
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay between retries (seconds)
        max_delay: Maximum delay between retries (seconds)
        strategy: Backoff strategy
        multiplier: Multiplier for exponential backoff
        retryable_exceptions: Exceptions to retry on
        non_retryable_exceptions: Exceptions to never retry
        on_retry: Callback called on each retry

    Example:
        @retry(max_attempts=3, retryable_exceptions=(ConnectionError,))
        def fetch_data():
            return requests.get(url)
    """
    config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        strategy=strategy,
        multiplier=multiplier,
        retryable_exceptions=retryable_exceptions,
        non_retryable_exceptions=non_retryable_exceptions
    )

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except config.non_retryable_exceptions:
                    raise
                except config.retryable_exceptions as e:
                    last_exception = e

                    if attempt == config.max_attempts:
                        logger.error(
                            f"All {config.max_attempts} attempts failed for {func.__name__}",
                            exc_info=True
                        )
                        raise

                    delay = config.get_delay(attempt)
                    logger.warning(
                        f"Attempt {attempt}/{config.max_attempts} failed for {func.__name__}: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )

                    if on_retry:
                        on_retry(e, attempt)

                    time.sleep(delay)

            raise last_exception

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except config.non_retryable_exceptions:
                    raise
                except config.retryable_exceptions as e:
                    last_exception = e

                    if attempt == config.max_attempts:
                        logger.error(
                            f"All {config.max_attempts} attempts failed for {func.__name__}",
                            exc_info=True
                        )
                        raise

                    delay = config.get_delay(attempt)
                    logger.warning(
                        f"Attempt {attempt}/{config.max_attempts} failed for {func.__name__}: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )

                    if on_retry:
                        on_retry(e, attempt)

                    await asyncio.sleep(delay)

            raise last_exception

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# Circuit Breaker Implementation
class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: float = 30.0  # Seconds before attempting recovery
    excluded_exceptions: Tuple[Type[Exception], ...] = ()


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""
    pass


@dataclass
class CircuitBreaker:
    """Circuit breaker for external service protection.

    Prevents cascading failures by stopping calls to failing services.

    States:
        CLOSED: Normal operation, requests pass through
        OPEN: Service is failing, requests are rejected immediately
        HALF_OPEN: Testing recovery, limited requests allowed

    Example:
        breaker = CircuitBreaker(name="api_service")

        @breaker
        def call_api():
            return requests.get(api_url)
    """
    name: str
    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _last_failure_time: Optional[datetime] = field(default=None, init=False)
    _listeners: List[Callable[[str, CircuitState], None]] = field(
        default_factory=list, init=False
    )

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        if self._state == CircuitState.OPEN:
            if self._should_attempt_recovery():
                self._transition_to(CircuitState.HALF_OPEN)
        return self._state

    def _should_attempt_recovery(self) -> bool:
        """Check if timeout has passed for recovery attempt."""
        if self._last_failure_time is None:
            return True
        elapsed = (datetime.utcnow() - self._last_failure_time).total_seconds()
        return elapsed >= self.config.timeout

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        old_state = self._state
        self._state = new_state

        logger.info(
            f"Circuit breaker '{self.name}' transitioned: {old_state.value} -> {new_state.value}"
        )

        for listener in self._listeners:
            try:
                listener(self.name, new_state)
            except Exception as e:
                logger.error(f"Circuit breaker listener error: {e}")

    def record_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.success_threshold:
                self._success_count = 0
                self._failure_count = 0
                self._transition_to(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self, exception: Exception) -> None:
        """Record a failed call."""
        if isinstance(exception, self.config.excluded_exceptions):
            return

        self._failure_count += 1
        self._last_failure_time = datetime.utcnow()

        if self._state == CircuitState.HALF_OPEN:
            self._success_count = 0
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.config.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def add_listener(self, listener: Callable[[str, CircuitState], None]) -> None:
        """Add state change listener."""
        self._listeners.append(listener)

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator to wrap function with circuit breaker."""

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            if self.state == CircuitState.OPEN:
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN. Service unavailable."
                )

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure(e)
                raise

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            if self.state == CircuitState.OPEN:
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN. Service unavailable."
                )

            try:
                result = await func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure(e)
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper


# Pre-configured circuit breakers for common external services
anthropic_breaker = CircuitBreaker(
    name="anthropic_api",
    config=CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=2,
        timeout=60.0
    )
)

ffmpeg_breaker = CircuitBreaker(
    name="ffmpeg",
    config=CircuitBreakerConfig(
        failure_threshold=3,
        success_threshold=1,
        timeout=30.0
    )
)

edge_tts_breaker = CircuitBreaker(
    name="edge_tts",
    config=CircuitBreakerConfig(
        failure_threshold=5,
        success_threshold=2,
        timeout=45.0
    )
)
