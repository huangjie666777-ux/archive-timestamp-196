import hashlib
import tempfile
from pathlib import Path

import pytest
from asn1crypto import tsp
from asn1crypto.parser import parse as asn1parse
from fastapi.testclient import TestClient

from tsa_server.app import create_app
from tsa_server.config import Config

POLICY = "1.3.6.1.4.1.55555.1.1"
CT = {"content-type": "application/timestamp-query"}


def make_config(**kw):
    defaults = dict(
        data_dir=Path(tempfile.mkdtemp()),
        policy_oid=POLICY,
        max_request_bytes=16384,
        max_concurrency=4,
        sign_timeout_seconds=5,
        accuracy_seconds=1,
    )
    defaults.update(kw)
    return Config(**defaults)


def make_req(data=b"hello", alg="sha256", nonce=42, cert_req=False, policy=None):
    digest = hashlib.new(alg, data).digest()
    req = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": alg},
                    "hashed_message": digest,
                }
            ),
            "cert_req": cert_req,
        }
    )
    if nonce is not None:
        req["nonce"] = nonce
    if policy is not None:
        req["req_policy"] = policy
    return req.dump()


def status_of(der):
    return tsp.PKIStatusInfo.load(asn1parse(der)[4]).native


@pytest.fixture()
def client():
    app = create_app(make_config())
    with TestClient(app) as c:
        yield c


def test_granted_with_nonce_and_certs(client):
    r = client.post("/tsa", content=make_req(nonce=7, cert_req=True), headers=CT)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/timestamp-reply"
    resp = tsp.TimeStampResp.load(r.content)
    assert resp["status"]["status"].native == "granted"
    sd = resp["time_stamp_token"]["content"]
    tst = sd["encap_content_info"]["content"].parsed
    assert tst["nonce"].native == 7
    assert tst["policy"].native == POLICY
    assert tst["serial_number"].native >= 1
    assert tst["message_imprint"]["hashed_message"].native == hashlib.sha256(b"hello").digest()
    assert len(sd["certificates"]) == 2  # tsa + root


def test_no_nonce_no_certs_by_default(client):
    r = client.post("/tsa", content=make_req(nonce=None), headers=CT)
    resp = tsp.TimeStampResp.load(r.content)
    sd = resp["time_stamp_token"]["content"]
    tst = sd["encap_content_info"]["content"].parsed
    assert tst["nonce"].native is None
    assert len(sd["certificates"]) == 0


def test_sha384_accepted(client):
    r = client.post("/tsa", content=make_req(alg="sha384"), headers=CT)
    resp = tsp.TimeStampResp.load(r.content)
    assert resp["status"]["status"].native == "granted"


def test_matching_policy_accepted(client):
    r = client.post("/tsa", content=make_req(policy=POLICY), headers=CT)
    resp = tsp.TimeStampResp.load(r.content)
    assert resp["status"]["status"].native == "granted"


def test_unknown_policy_rejected(client):
    r = client.post("/tsa", content=make_req(policy="1.2.3.4"), headers=CT)
    assert status_of(r.content)["fail_info"] == {"unaccepted_policy"}


def test_bad_algorithm_rejected(client):
    r = client.post("/tsa", content=make_req(alg="sha1"), headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_alg"}


def test_digest_length_mismatch_rejected(client):
    req = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": "sha256"},
                    "hashed_message": b"\x00" * 16,
                }
            ),
        }
    )
    r = client.post("/tsa", content=req.dump(), headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_data_format"}


def test_trailing_bytes_rejected(client):
    r = client.post("/tsa", content=make_req() + b"\x00", headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_data_format"}


def test_garbage_rejected(client):
    r = client.post("/tsa", content=b"not der at all", headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_data_format"}


def test_extensions_rejected(client):
    req = tsp.TimeStampReq.load(make_req())
    req["extensions"] = tsp.Extensions(
        [tsp.Extension({"extn_id": "1.2.3.4", "critical": False, "extn_value": b"\x05\x00"})]
    )
    r = client.post("/tsa", content=req.dump(), headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_request"}


def test_version_2_rejected(client):
    req = tsp.TimeStampReq.load(make_req())
    req["version"] = 2
    r = client.post("/tsa", content=req.dump(), headers=CT)
    assert status_of(r.content)["fail_info"] == {"bad_request"}


def test_wrong_content_type(client):
    assert client.post("/tsa", content=make_req(), headers={"content-type": "text/plain"}).status_code == 415


def test_oversize_rejected(client):
    r = client.post("/tsa", content=b"\x30" * 20000, headers=CT)
    assert r.status_code == 413


def test_serials_unique_and_sequential(client):
    serials = []
    for _ in range(5):
        r = client.post("/tsa", content=make_req(), headers=CT)
        resp = tsp.TimeStampResp.load(r.content)
        serials.append(
            resp["time_stamp_token"]["content"]["encap_content_info"]["content"]
            .parsed["serial_number"]
            .native
        )
    assert len(set(serials)) == 5
    assert serials == sorted(serials)


def test_receipt_roundtrip_and_404(client):
    r = client.post("/tsa", content=make_req(), headers=CT)
    resp = tsp.TimeStampResp.load(r.content)
    serial = (
        resp["time_stamp_token"]["content"]["encap_content_info"]["content"]
        .parsed["serial_number"]
        .native
    )
    got = client.get(f"/tsa/receipt/{serial}")
    assert got.status_code == 200
    assert got.content == r.content
    assert client.get("/tsa/receipt/999999").status_code == 404


def test_cert_endpoint(client):
    r = client.get("/tsa/cert")
    assert r.status_code == 200
    assert r.text.count("BEGIN CERTIFICATE") == 2


def test_restart_reuses_pki_and_db():
    data_dir = Path(tempfile.mkdtemp())
    app1 = create_app(make_config(data_dir=data_dir))
    with TestClient(app1) as c1:
        r1 = c1.post("/tsa", content=make_req(), headers=CT)
        pem1 = c1.get("/tsa/cert").text
    app2 = create_app(make_config(data_dir=data_dir))
    with TestClient(app2) as c2:
        assert c2.get("/tsa/cert").text == pem1
        r2 = c2.post("/tsa", content=make_req(), headers=CT)
        s1 = tsp.TimeStampResp.load(r1.content)["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed["serial_number"].native
        s2 = tsp.TimeStampResp.load(r2.content)["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed["serial_number"].native
        assert s2 > s1
        assert c2.get(f"/tsa/receipt/{s1}").content == r1.content


def test_key_mismatch_refuses_startup():
    data_dir = Path(tempfile.mkdtemp())
    app = create_app(make_config(data_dir=data_dir))
    with TestClient(app):
        pass
    # replace tsa.key with a fresh, non-matching key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (data_dir / "tsa.key").write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    app2 = create_app(make_config(data_dir=data_dir))
    with pytest.raises(RuntimeError, match="does not match"):
        with TestClient(app2):
            pass

