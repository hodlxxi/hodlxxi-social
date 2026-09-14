"""Real JS consumer, actual pinned services and migrations; no Python consumer.

Only this explicitly selected guarded fixture exports a synthetic signer socket.
The participant private key never crosses it. Infrastructure material travels
over child stdin into the confidential Node server and is never logged.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading

import pytest
from coincurve import PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select
from werkzeug.serving import make_server, WSGIRequestHandler
from app.services.social_session_issuance import SocialSessionIssuance
from tests.integration.test_social_session_issuance_postgresql import (
    postgres_factory, mobile_factory, generation_factory, state, material,
    replay_ready, issuance_ready, ingress_live, live,
    test_no_issuance_from_incomplete_or_unsigned_history,
    test_substitution_never_issues_again_or_redirects_recovery,
    test_old_backend_capabilities_cannot_issue,
    test_signed_service_claim_substitutions_denied,
    test_new_transport_errors_and_assertion_replay_are_closed,
    test_another_issuer_or_client_cannot_recover,
)
from tests.unit.test_social_mobile_authorization_ingress import ISSUER, BACKEND


def test_real_javascript_browser_bff_ubid(live):
    out = Path(os.environ["UBID_TEST_OUTPUT"])
    events = []
    signs = []

    def application(environ, start_response):
        path = environ["PATH_INFO"]
        # Test-only external NIP-07 provider: receives/returns public events only.
        if path == "/__synthetic/sign":
            assert environ["REQUEST_METHOD"] == "POST"
            size = int(environ["CONTENT_LENGTH"])
            assert 0 < size < 16384
            unsigned = json.loads(environ["wsgi.input"].read(size))
            assert set(unsigned) == {"content", "created_at", "kind", "tags"}
            event = dict(unsigned, pubkey=live["subject"])
            preimage = [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]
            event["id"] = hashlib.sha256(json.dumps(preimage, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            event["sig"] = PrivateKey((3).to_bytes(32, "big")).sign_schnorr(bytes.fromhex(event["id"]), b"\0" * 32).hex()
            signs.append(event["id"])
            body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]

        def observe(status, headers, exc_info=None):
            events.append({"path": path, "status": int(status.split()[0])})
            return start_response(status, headers, exc_info)
        return live["app"](environ, observe)

    class Quiet(WSGIRequestHandler):
        def log_request(self, *args, **kwargs):
            pass

    server = make_server("unix://" + os.environ["SOCIAL_UBID_SOCKET"], 0, application, threaded=True, request_handler=Quiet)
    thread = threading.Thread(target=server.serve_forever, name="owned-social-ubid-bridge")
    thread.start()
    config = dict(subject=live["subject"], viewerAccessToken=live["bearer"], issuerOrigin=ISSUER,
                  clientId=BACKEND, now=live["runtime"].mobile._now() * 1000,
                  backendKey=live["material"][0].private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
    try:
        with (out / "javascript.log").open("w") as log:
            completed = subprocess.run(["/usr/bin/node", str(Path(os.environ["SOCIAL_SOURCE"]) / "tests/support/social-mobile-ubid/consumer.mjs")],
                input=json.dumps(config), text=True, stdout=log, stderr=subprocess.STDOUT, timeout=60, check=False)
        assert completed.returncode == 0, "real JavaScript consumer failed; see javascript.log"
        with live["state"][1]() as db:
            assert db.scalar(select(func.count()).select_from(SocialSessionIssuance)) == 1
        assert len(signs) == 1
    finally:
        server.shutdown()
        thread.join(timeout=10)
        server.server_close()
        assert not thread.is_alive()
        (out / "bridge-events.json").write_text(json.dumps({"events": events, "explicit_sign_count": len(signs), "bridge_stopped": True}, indent=2))
