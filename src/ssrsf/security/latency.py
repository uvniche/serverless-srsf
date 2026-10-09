from __future__ import annotations

import functools
import time
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def uniform_latency(minimum_ms: int) -> Callable[[F], F]:
    """Apply a shared response floor to role-distinct externally observable paths."""

    def decorate(function: F) -> F:
        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            started = time.monotonic()
            try:
                return function(*args, **kwargs)
            finally:
                remaining = minimum_ms / 1000 - (time.monotonic() - started)
                if remaining > 0:
                    time.sleep(remaining)
        return wrapped  # type: ignore[return-value]
    return decorate

