"""RFC 3161 request parsing, TSTInfo construction and CMS signing."""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass

from asn1crypto import algos, cms, core, tsp, x509 as asn1x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ALLOWED_HASHES = {"sha256": 32, "sha384": 48}
HASHLIB = {"sha256": hashlib.sha256, "sha384": hashlib.sha384}
CRYPTO_HASH = {"sha256": hashes.SHA256, "sha384": hashes.SHA384}


class Rejection(Exception):
    """Maps to a PKIStatusInfo with status=rejection and a failInfo bit."""

    def __init__(self, fail_info: str, detail: str = ""):
        super().__init__(detail or fail_info)
        self.fail_info = fail_info


@dataclass
class ParsedRequest:
    hash_alg: str
    nonce: int | None
    cert_req: bool


def parse_request(data: bytes) -> ParsedRequest:
    try:
        req = tsp.TimeStampReq.load(data, strict=True)
    except (ValueError, TypeError) as exc:
        raise Rejection("bad_data_format", f"not a valid DER TimeStampReq: {exc}")
    if req.dump() != data:
        raise Rejection("bad_data_format", "non-canonical DER or trailing bytes")

    if req["version"].native != "v1":
        raise Rejection("bad_request", "only version 1 is supported")

    imprint = req["message_imprint"]
    alg = imprint["hash_algorithm"]["algorithm"].native
    if alg not in ALLOWED_HASHES:
        raise Rejection("bad_alg", f"unsupported hash algorithm: {alg}")
    digest = imprint["hashed_message"].native
    if not isinstance(digest, bytes) or len(digest) != ALLOWED_HASHES[alg]:
        raise Rejection("bad_data_format", "hashedMessage length mismatch")

    if len(req["extensions"]) > 0:
        raise Rejection("bad_request", "extensions are not accepted")

    return ParsedRequest(
        hash_alg=alg,
        nonce=req["nonce"].native if req["nonce"].native is not None else None,
        cert_req=bool(req["cert_req"].native),
    )


def check_policy(req_der: bytes, expected_oid: str) -> None:
    req = tsp.TimeStampReq.load(req_der, strict=True)
    policy = req["req_policy"].native
    if policy is not None and policy != expected_oid:
        raise Rejection("unaccepted_policy", f"unknown policy: {policy}")


def _utc_seconds(when: dt.datetime) -> dt.datetime:
    return when.astimezone(dt.timezone.utc).replace(microsecond=0)


def build_tst_info(
    req_der: bytes,
    policy_oid: str,
    serial: int,
    gen_time: dt.datetime,
    accuracy_seconds: int,
) -> bytes:
    req = tsp.TimeStampReq.load(req_der, strict=True)
    info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": policy_oid,
            "message_imprint": req["message_imprint"],
            "serial_number": serial,
            "gen_time": tsp.GeneralizedTime(_utc_seconds(gen_time)),
            "accuracy": tsp.Accuracy({"seconds": accuracy_seconds}),
        }
    )
    if req["nonce"].native is not None:
        info["nonce"] = req["nonce"]
    return info.dump()


def _ess_signing_cert_v2(cert_der: bytes, cert: asn1x509.Certificate) -> tsp.SigningCertificateV2:
    ess = tsp.ESSCertIDv2(
        {
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "cert_hash": hashlib.sha256(cert_der).digest(),
            "issuer_serial": tsp.IssuerSerial(
                {
                    "issuer": [
                        asn1x509.GeneralName(
                            {
                                "directory_name": asn1x509.Name.load(
                                    cert["tbs_certificate"]["issuer"].dump()
                                )
                            }
                        )
                    ],
                    "serial_number": cert["tbs_certificate"]["serial_number"],
                }
            ),
        }
    )
    return tsp.SigningCertificateV2({"certs": tsp.ESSCertIDv2s([ess])})


def sign_token(
    tst_info_der: bytes,
    hash_alg: str,
    tsa_cert_der: bytes,
    tsa_cert_asn1: asn1x509.Certificate,
    chain_cert_ders: list[bytes],
    private_key,
    include_certs: bool,
    gen_time: dt.datetime,
) -> bytes:
    """Return a DER ContentInfo holding the signed time-stamp token."""
    digest = HASHLIB[hash_alg](tst_info_der).digest()
    attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [
                        cms.Time({"utc_time": cms.UTCTime(_utc_seconds(gen_time))})
                    ],
                }
            ),
            cms.CMSAttribute(
                {
                    "type": "signing_certificate_v2",
                    "values": [_ess_signing_cert_v2(tsa_cert_der, tsa_cert_asn1)],
                }
            ),
        ]
    )
    signature = private_key.sign(
        attrs.dump(), padding.PKCS1v15(), CRYPTO_HASH[hash_alg]()
    )
    signer = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1x509.Name.load(
                                tsa_cert_asn1["tbs_certificate"]["issuer"].dump()
                            ),
                            "serial_number": tsa_cert_asn1["tbs_certificate"][
                                "serial_number"
                            ],
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": hash_alg}),
            "signed_attrs": attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            ),
            "signature": signature,
        }
    )
    encap = cms.EncapsulatedContentInfo(
        {"content_type": "tst_info", "content": tsp.TSTInfo.load(tst_info_der)}
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": cms.DigestAlgorithms(
                [algos.DigestAlgorithm({"algorithm": hash_alg})]
            ),
            "encap_content_info": encap,
            "signer_infos": cms.SignerInfos([signer]),
        }
    )
    if include_certs:
        certs = [cms.CertificateChoices({"certificate": tsa_cert_asn1})]
        for der in chain_cert_ders:
            certs.append(
                cms.CertificateChoices({"certificate": asn1x509.Certificate.load(der)})
            )
        signed_data["certificates"] = cms.CertificateSet(certs)
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


def response_granted(token_der: bytes) -> bytes:
    return tsp.TimeStampResp(
        {
            "status": tsp.PKIStatusInfo({"status": "granted"}),
            "time_stamp_token": cms.ContentInfo.load(token_der),
        }
    ).dump()


def response_rejection(fail_info: str) -> bytes:
    class _Resp(core.Sequence):
        _fields = [("status", tsp.PKIStatusInfo)]

    return _Resp(
        {
            "status": tsp.PKIStatusInfo(
                {
                    "status": "rejection",
                    "fail_info": tsp.PKIFailureInfo({fail_info}),
                }
            )
        }
    ).dump()
