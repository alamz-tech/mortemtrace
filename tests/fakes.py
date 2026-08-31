"""In-memory fake of the google.cloud.firestore client surface that
data/scope_store.py actually uses: collection/document/subcollection
addressing, get/set/create, where/limit/order_by/stream, and
transactions. Enough to unit-test scope enforcement, idempotency,
source-id rejection, and concurrent read-modify-write without live GCP
credentials or the Firestore emulator.

Deliberate fidelity choices, because a fake that is wrong in the same
direction as the code it tests proves nothing:

  - `create()` raises google.api_core.exceptions.AlreadyExists, the real
    exception type scope_store catches, rather than a stand-in.
  - `run_transaction()` really serialises with a lock, so a test can spawn
    real threads and observe that concurrent appends do not lose writes.
  - `document()` splits on "/" exactly as Firestore does, which is what
    makes an unvalidated org_id a path-traversal concern rather than a
    theoretical one.

What it still does NOT model, and therefore cannot protect against - the
Firestore emulator tier is the right place for these: the 1 MiB document
limit, composite index requirements, and real query-planner semantics.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from google.api_core.exceptions import AlreadyExists


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

    @property
    def path(self) -> tuple[str, ...]:
        return self._path

    def get(self, transaction: Any = None, timeout: Optional[float] = None) -> _Snapshot:
        data = self._store._docs.get(self._path)
        return _Snapshot(self._path[-1], data)

    def set(self, data: dict, timeout: Optional[float] = None) -> None:
        self._store._docs[self._path] = dict(data)

    def create(self, data: dict, timeout: Optional[float] = None) -> None:
        """Atomic create-if-absent, mirroring Firestore's own semantics.

        Guarded by the store lock so concurrent callers cannot both
        succeed - that is precisely the property scope_store relies on for
        idempotency-key suppression under duplicate Pub/Sub delivery.
        """
        with self._store._lock:
            if self._path in self._store._docs:
                raise AlreadyExists(f"document already exists: {'/'.join(self._path)}")
            self._store._docs[self._path] = dict(data)

    def delete(self, timeout: Optional[float] = None) -> None:
        self._store._docs.pop(self._path, None)

    def collection(self, name: str) -> "_CollectionRef":
        return _CollectionRef(self._store, self._path + (name,))


class _FakeTransaction:
    """Buffers writes and applies them at commit, like the real one.

    Buffering matters for test fidelity: code that reads a document,
    mutates it, and writes it back inside a transaction must not see its
    own uncommitted write on a subsequent read within the same
    transaction body.
    """

    def __init__(self, store: "FakeFirestore"):
        self._store = store
        self._pending: list[tuple[tuple[str, ...], dict]] = []

    def set(self, doc_ref: _DocRef, data: dict) -> None:
        self._pending.append((doc_ref.path, dict(data)))

    def _commit(self) -> None:
        for path, data in self._pending:
            self._store._docs[path] = data
        self._pending.clear()


def _match(data: dict, field: str, op: str, value: Any) -> bool:
    actual = data.get(field)
    if op == "==":
        return actual == value
    if op == "!=":
        return actual != value
    if op == "in":
        return actual in value
    if op == "array_contains":
        return isinstance(actual, list) and value in actual
    if op == ">=":
        return actual is not None and actual >= value
    if op == "<=":
        return actual is not None and actual <= value
    raise NotImplementedError(f"fake firestore does not support op {op!r}")


class _Query:
    def __init__(self, store: "FakeFirestore", path: tuple[str, ...],
                 filters: Optional[list] = None, limit: Optional[int] = None,
                 order_by: Optional[list[tuple[str, str]]] = None):
        self._store = store
        self._path = path
        self._filters = filters or []
        self._limit = limit
        self._order_by = order_by or []

    def where(self, field: str = None, op: str = None, value: Any = None,
              *, filter: Any = None) -> "_Query":
        """Accepts the modern keyword `filter=FieldFilter(...)` form that
        scope_store uses, and the legacy positional form, so the fake
        mirrors the real client's actual surface rather than only the part
        this codebase happens to call today."""
        if filter is not None:
            field, op, value = filter.field_path, filter.op_string, filter.value
        return _Query(self._store, self._path, self._filters + [(field, op, value)],
                      self._limit, self._order_by)

    def limit(self, n: int) -> "_Query":
        return _Query(self._store, self._path, self._filters, n, self._order_by)

    def order_by(self, field: str, direction: str = "ASCENDING") -> "_Query":
        return _Query(self._store, self._path, self._filters, self._limit,
                      self._order_by + [(field, direction)])

    def stream(self, timeout: Optional[float] = None):
        prefix_len = len(self._path) + 1
        results = []
        for path, data in list(self._store._docs.items()):
            if len(path) != prefix_len or path[:-1] != self._path:
                continue
            if all(_match(data, f, op, v) for f, op, v in self._filters):
                results.append(_Snapshot(path[-1], data))

        for field, direction in reversed(self._order_by):
            results.sort(
                key=lambda s: (s.to_dict() or {}).get(field) or "",
                reverse=direction.upper().startswith("DESC"),
            )

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
        self._lock = threading.RLock()
        self._txn_lock = threading.RLock()

    def collection(self, name: str) -> _CollectionRef:
        return _CollectionRef(self, (name,))

    def run_transaction(self, body: Callable[[_FakeTransaction], Any]) -> Any:
        """Serialised read-modify-write.

        scope_store.update_in_transaction() prefers this hook when the
        client exposes it, which is what lets the unit suite drive genuine
        concurrent threads through the same code path production uses.
        """
        with self._txn_lock:
            transaction = _FakeTransaction(self)
            result = body(transaction)
            transaction._commit()
            return result

    def seed(self, path: str, data: dict) -> None:
        """Test convenience: write a document by slash-separated path."""
        self._docs[tuple(path.split("/"))] = dict(data)
