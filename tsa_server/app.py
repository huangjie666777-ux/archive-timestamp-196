"""FastAPI HTTP layer: POST /tsa, certificate and receipt retrieval."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt

from asn1crypto import x509 as asn1x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse

from . import pki, rfc3161
from .config import Config
from .store import ClockMovedBackwards, Store

QUERY_MEDIA = "application/timestamp-query"
REPLY_MEDIA = "application/timestamp-reply"


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.from_env()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.config = config
        app.state.pki = pki.load_or_create(config.data_dir)
        app.state.store = Store(config.data_dir / "receipts.db")
        app.state.slots = asyncio.BoundedSemaphore(config.max_concurrency)
        yield
        app.state.store.close()

    app = FastAPI(title="RFC 3161 Time-Stamp Authority", lifespan=lifespan)

    def _sign_and_record(body: bytes, parsed: rfc3161.ParsedRequest) -> bytes:
        state = app.state
        key = state.pki.tsa_key
        tsa_der = state.pki.tsa_cert.public_bytes(serialization.Encoding.DER)
        tsa_asn1 = asn1x509.Certificate.load(tsa_der)
        chain = [state.pki.root_cert.public_bytes(serialization.Encoding.DER)]

        def sign(serial: int, gen_time: dt.datetime) -> bytes:
            tst = rfc3161.build_tst_info(
                body, config.policy_oid, serial, gen_time, config.accuracy_seconds
            )
            token = rfc3161.sign_token(
                tst,
                parsed.hash_alg,
                tsa_der,
                tsa_asn1,
                chain,
                key,
                parsed.cert_req,
                gen_time,
            )
            return rfc3161.response_granted(token)

        _, _, reply = state.store.issue(sign)
        return reply

    @app.post("/tsa")
    async def timestamp(request: Request) -> Response:
        if request.headers.get("content-type", "").split(";")[0].strip() != QUERY_MEDIA:
            raise HTTPException(415, "expected application/timestamp-query")
        length = request.headers.get("content-length")
        if length is not None and int(length) > config.max_request_bytes:
            raise HTTPException(413, "request too large")
        body = await request.body()
        if len(body) > config.max_request_bytes:
            raise HTTPException(413, "request too large")

        try:
            parsed = rfc3161.parse_request(body)
            rfc3161.check_policy(body, config.policy_oid)
        except rfc3161.Rejection as rej:
            return Response(
                rfc3161.response_rejection(rej.fail_info), media_type=REPLY_MEDIA
            )

        slots = app.state.slots
        if slots.locked() and slots._value == 0:  # noqa: SLF001 - fast reject
            raise HTTPException(503, "too many concurrent requests")
        async with slots:
            loop = asyncio.get_running_loop()
            try:
                reply = await asyncio.wait_for(
                    loop.run_in_executor(None, _sign_and_record, body, parsed),
                    timeout=config.sign_timeout_seconds,
                )
            except asyncio.TimeoutError:
                raise HTTPException(503, "signing timed out") from None
            except ClockMovedBackwards:
                raise HTTPException(
                    503, "system clock moved backwards; issuance refused"
                ) from None
        return Response(reply, media_type=REPLY_MEDIA)

    @app.get("/tsa/cert", response_class=PlainTextResponse)
    async def certificate_chain() -> str:
        state = app.state
        pem = serialization.Encoding.PEM
        return (
            state.pki.tsa_cert.public_bytes(pem).decode()
            + state.pki.root_cert.public_bytes(pem).decode()
        )

    @app.get("/tsa/receipt/{serial}")
    async def receipt(serial: int) -> Response:
        data = app.state.store.get(serial)
        if data is None:
            raise HTTPException(404, "unknown serial number")
        return Response(data, media_type=REPLY_MEDIA)

    return app


app = create_app()

