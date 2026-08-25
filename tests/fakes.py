"""In-memory fake of the google.cloud.firestore client surface that
data/scope_store.py actually uses: collection/document/subcollection
addressing, get/set, and where/limit/stream. Enough to unit-test scope
enforcement, idempotency, and source-id rejection without live GCP
credentials or the Firestore emulator.
"""
from __future__ import annotations

from typing import Any, Optional


class _Snapshot:
    def __init__(self, doc_id: str, data: Optional[dict]):
        self.id = doc_id
        self._data = data
        self.exists = data is not None

    def to_dict(self) -> Optional[dict]:
        return dict(self._data) if self._data is not None else None


class _DocRef:
    def __init__(self, store: "FakeFirestore", path: tuple[str, ...]):
        self._store = store
        self._path = path

    def get(self) -> _Snapshot:
        data = self._store._docs.get(self._path)
        return _Snapshot(self._path[-1], data)

    def set(self, data: dict) -> None:
        self._store._docs[self._path] = dict(data)

    def collection(self, name: str) -> "_CollectionRef":
        return _CollectionRef(self._store, self._path + (name,))


def _match(data: dict, field: str, op: str, value: Any) -> bool:
    actual = data.get(field)
    if op == "==":
        return actual == value
    if op == "in":
        return actual in value
    if op == "array_contains":
        return isinstance(actual, list) and value in actual
    raise NotImplementedError(f"fake firestore does not support op {op!r}")


class _Query:
    def __init__(self, store: "FakeFirestore", path: tuple[str, ...],
                 filters: Optional[list] = None, limit: Optional[int] = None):
        self._store = store
        self._path = path
        self._filters = filters or []
        self._limit = limit

    def where(self, field: str, op: str, value: Any) -> "_Query":
        return _Query(self._store, self._path, self._filters + [(field, op, value)], self._limit)

    def limit(self, n: int) -> "_Query":
        return _Query(self._store, self._path, self._filters, n)

    def stream(self):
        prefix_len = len(self._path) + 1
        results = []
        for path, data in self._store._docs.items():
            if len(path) != prefix_len or path[:-1] != self._path:
                continue
            if all(_match(data, f, op, v) for f, op, v in self._filters):
                results.append(_Snapshot(path[-1], data))
        if self._limit:
            results = results[: self._limit]
        return results


class _CollectionRef(_Query):
    def document(self, doc_id: str) -> _DocRef:
        # Mirrors real Firestore: a slash-separated relative path alternates
        # document/collection segments, e.g. "agent_name/versions/1.0.0".
        segments = tuple(doc_id.split("/"))
        return _DocRef(self._store, self._path + segments)


class FakeFirestore:
    """Drop-in for scope_store.set_client() in tests."""

    def __init__(self):
        self._docs: dict[tuple[str, ...], dict] = {}

    def collection(self, name: str) -> _CollectionRef:
        return _CollectionRef(self, (name,))

    def seed(self, path: str, data: dict) -> None:
        """Test convenience: write a document by slash-separated path."""
        self._docs[tuple(path.split("/"))] = dict(data)
