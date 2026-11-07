#!/usr/bin/env python3
"""Runs the real FilterPhone device API locally for contract tests of the Windows client.

The API code is yeled-tov/filterphone/server at a pinned commit (see BACKEND_COMMIT in the CI workflow).
Only the parts that need root or production infrastructure are replaced, exactly as the backend's own
test-suite does (server/tests/helpers.py): WireGuard by FakeWG and Redis by fakeredis. Nothing here talks
to the production server.

Usage: backend_harness.py <filterphone/server dir> <port> <info.json>
Writes {"base_url", "code", "admin_user", "admin_password"} to info.json, then serves until killed.
"""
from __future__ import annotations

import datetime
import json
import secrets
import sys
import tempfile
from pathlib import Path


def make_ca(path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mitmproxy"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mitmproxy")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> int:
    server_dir, port, info_path = Path(sys.argv[1]).resolve(), int(sys.argv[2]), Path(sys.argv[3])
    sys.path.insert(0, str(server_dir))
    sys.path.insert(0, str(server_dir / "tests"))

    import fakeredis
    import uvicorn
    from helpers import FakeWG  # the backend's own WireGuard test double

    from filterphone.api import db
    from filterphone.api.app import create_app
    from filterphone.api.service import Services
    from filterphone.settings import Settings

    tmp = Path(tempfile.mkdtemp(prefix="fp-contract-"))
    ca = tmp / "ca.pem"
    make_ca(ca)
    cfg = Settings(data_dir=str(tmp), run_dir=str(tmp), mitm_ca_cert=str(ca), public_ip="151.145.88.42",
                   adguard_url="http://127.0.0.1:9")
    db.init(cfg.db_path)
    svc = Services(cfg, FakeWG(), fakeredis.FakeRedis(decode_responses=True))
    admin_password = secrets.token_urlsafe(16)
    svc.set_admin("contract-admin", admin_password)
    code = svc.create_code("windows-contract", level=2, uses=20, expires_days=1)["code"]
    info_path.write_text(json.dumps({"base_url": f"http://127.0.0.1:{port}", "code": code,
                                     "admin_user": "contract-admin", "admin_password": admin_password}))
    uvicorn.run(create_app(svc), host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
