"""Server-issued execution authorizations.

An authorization is an HMAC over the exact action fingerprint, issue/expiry
times and request id. The signing key lives only in the trusted server process,
so a client cannot mint one by adding a field such as ``approved: true``: the
request model forbids unknown fields, and the token is recomputed and compared
with a constant-time check before any tool runs.

Authorizations are single use: :meth:`AuthorizationService.consume` flips the
row from ``ISSUED`` to ``CONSUMED`` with an atomic conditional update.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass

from .db import Database
from .models import canonical_json, sha256_hex


class AuthorizationError(Exception):
    """Authorization could not be verified. Carries a reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail or reason_code


@dataclass(frozen=True)
class Authorization:
    """The token handed to the executor together with its identity."""

    authorization_id: str
    request_id: str
    fingerprint: str
    kind: str
    issued_at: float
    expires_at: float
    token: str

    def to_dict(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "kind": self.kind,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "token": self.token,
        }


class AuthorizationService:
    """Issues and verifies HMAC-bound, single-use execution authorizations."""

    def __init__(
        self,
        db: Database,
        secret: bytes | None = None,
        clock: "callable" = time.time,
        ttl_seconds: float = 300.0,
    ) -> None:
        self.db = db
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        env_secret = os.environ.get("AGENTSHIELD_AUTHZ_SECRET")
        if secret is not None:
            self._secret = bytes(secret)
        elif env_secret:
            self._secret = env_secret.encode("utf-8")
        else:
            # Ephemeral key: authorizations do not survive a process restart,
            # which is the safe default for a local prototype.
            self._secret = secrets.token_bytes(32)

    # -- token machinery ----------------------------------------------------
    def _signing_input(
        self,
        authorization_id: str,
        request_id: str,
        fingerprint: str,
        kind: str,
        issued_at: float,
        expires_at: float,
    ) -> str:
        return canonical_json(
            {
                "authorization_id": authorization_id,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
                "issued_at": issued_at,
                "kind": kind,
                "request_id": request_id,
            }
        )

    def _sign(self, signing_input: str) -> str:
        return hmac.new(
            self._secret, signing_input.encode("utf-8"), "sha256"
        ).hexdigest()

    # -- lifecycle ----------------------------------------------------------
    def issue(self, request_id: str, fingerprint: str, kind: str) -> Authorization:
        """Create a server-side authorization bound to one exact action."""
        now = float(self.clock())
        authorization_id = "az_" + uuid.uuid4().hex
        expires_at = now + self.ttl_seconds
        token = self._sign(
            self._signing_input(
                authorization_id, request_id, fingerprint, kind, now, expires_at
            )
        )
        self.db.execute(
            "INSERT INTO authorizations "
            "(authorization_id, request_id, fingerprint, kind, token, state, "
            " issued_at, expires_at) VALUES (?, ?, ?, ?, ?, 'ISSUED', ?, ?)",
            (authorization_id, request_id, fingerprint, kind, token, now, expires_at),
        )
        return Authorization(
            authorization_id=authorization_id,
            request_id=request_id,
            fingerprint=fingerprint,
            kind=kind,
            issued_at=now,
            expires_at=expires_at,
            token=token,
        )

    def verify(self, authorization: Authorization) -> None:
        """Raise :class:`AuthorizationError` unless the token is valid and usable."""
        row = self.db.query_one(
            "SELECT * FROM authorizations WHERE authorization_id = ?",
            (authorization.authorization_id,),
        )
        if row is None:
            raise AuthorizationError(
                "unknown_authorization", authorization.authorization_id
            )

        expected_token = self._sign(
            self._signing_input(
                str(row["authorization_id"]),
                str(row["request_id"]),
                str(row["fingerprint"]),
                str(row["kind"]),
                float(row["issued_at"]),
                float(row["expires_at"]),
            )
        )
        if not hmac.compare_digest(expected_token, str(row["token"])):
            raise AuthorizationError("invalid_authorization", "stored token mismatch")
        if not hmac.compare_digest(str(row["token"]), authorization.token):
            raise AuthorizationError("invalid_authorization", "presented token mismatch")
        if row["request_id"] != authorization.request_id:
            raise AuthorizationError("authorization_mismatch", "request id differs")
        if row["fingerprint"] != authorization.fingerprint:
            raise AuthorizationError("authorization_mismatch", "action fingerprint differs")
        if row["state"] != "ISSUED":
            raise AuthorizationError("authorization_not_usable", str(row["state"]))
        if float(row["expires_at"]) <= float(self.clock()):
            raise AuthorizationError("authorization_expired", str(row["expires_at"]))

    def consume(self, authorization: Authorization) -> bool:
        """Atomically mark the authorization used. Returns False if already used."""
        cursor = self.db.execute(
            "UPDATE authorizations SET state = 'CONSUMED', consumed_at = ? "
            "WHERE authorization_id = ? AND state = 'ISSUED' AND fingerprint = ?",
            (float(self.clock()), authorization.authorization_id, authorization.fingerprint),
        )
        return cursor.rowcount == 1

    def token_fingerprint(self, token: str) -> str:
        """Convenience helper used by diagnostics: short digest of a token."""
        return sha256_hex(token)[:16]
