"""Reusable fail-closed wrapper for synchronous P3 decision components."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def fail_closed(fallback: Callable[[Exception], Any]) -> Callable[[F], F]:
    """Return a decorator that converts component exceptions to safe values."""

    def decorate(function: F) -> F:
        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                return fallback(exc)

        return wrapped  # type: ignore[return-value]

    return decorate
