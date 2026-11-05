"""A file work's restoration mapping, shared by its restore API and linked questions (#29).

PseudonymSession is not thread-safe, so the mapping is used by one request at a
time. The file work owns the mapping: only its expiry, discard, server shutdown,
or the close() that follows an internal take() ends it. A question linked to
the file only borrows the mapping, so the question's own cleanup never ends it.
"""
from __future__ import annotations

import threading


class MappingClosed(RuntimeError):
    """The file work has ended, and its mapping with it."""


class SharedMapping:
    def __init__(self, session):
        self._session = session
        self._use = threading.Lock()  # One process/restore at a time; may be held long.
        self._state = threading.Lock()  # Guards the flags below; only held briefly.
        self._busy = False
        self._closing = False

    def process(self, text: str):
        """Pseudonymize new text, numbering after the placeholders already assigned."""
        return self._run(self._session.process, text)

    def restore(self, text: str):
        return self._run(self._session.restore, text)

    def borrow(self) -> BorrowedMapping:
        return BorrowedMapping(self)

    def close(self) -> None:
        """End the mapping now, or right after the use in progress. Never waits.

        Callers hold the file store's lock, or run on the event loop.
        """
        with self._state:
            if self._closing:
                return
            self._closing = True
            if not self._busy:
                self._end()

    def _run(self, method, text):
        with self._use:
            with self._state:
                if self._closing:
                    raise MappingClosed()
                self._busy = True
            try:
                return method(text)
            finally:
                with self._state:
                    self._busy = False
                    if self._closing:
                        self._end()

    def _end(self) -> None:
        try:
            self._session.close()
        except Exception:
            # The mapping counts as ended either way; never log sensitive exceptions.
            pass


class BorrowedMapping:
    """A linked question's use of a file mapping. close() ends only this use."""

    def __init__(self, mapping: SharedMapping):
        self._mapping = mapping
        self._closed = False

    def process(self, text: str):
        self._check_open()
        return self._mapping.process(text)

    def restore(self, text: str):
        self._check_open()
        return self._mapping.restore(text)

    def close(self) -> None:
        self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise MappingClosed()
