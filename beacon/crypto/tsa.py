"""RFC 3161 Time-Stamp Protocol: local TSA and optional remote TSA."""

from __future__ import annotations

import base64
import datetime as dt
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from beacon.errors import E_TSA, fail

# RFC 3161 / CMS OIDs
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
OID_TST_INFO = bytes.fromhex("2a864886f70d0109100104")  # 1.2.840.113549.1.9.16.1.4
OID_SHA256 = bytes.fromhex("608648016503040201")  # 2.16.840.1.101.3.4.2.1
OID_RSA_SHA256 = bytes.fromhex("2a864886f70d01010b")  # 1.2.840.113549.1.1.11
OID_RSA_ENC = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1
OID_POLICY = bytes.fromhex("2b06010505070308")  # 1.3.6.1.5.5.7.3.8 timeStamping
OID_BEACON_POLICY = bytes.fromhex("2b06010401837a0101")  # 1.3.6.1.4.1.999.1.1 private test policy

TSA_KEY = "tsa.pem"
TSA_CERT = "tsa.crt"


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def der_oid(encoded: bytes) -> bytes:
    return _tlv(0x06, encoded)


def der_int(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        length = (value.bit_length() + 7) // 8
        raw = value.to_bytes(length, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _tlv(0x02, raw)


def der_octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def der_set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def der_null() -> bytes:
    return b"\x05\x00"


def der_gentime(when: dt.datetime) -> bytes:
    aware = when.astimezone(dt.timezone.utc).replace(microsecond=0)
    text = aware.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    return _tlv(0x18, text)


def der_explicit(n: int, body: bytes) -> bytes:
    return _tlv(0xA0 | n, body)


def der_implicit_set(n: int, body: bytes) -> bytes:
    return _tlv(0xA0 | n, body)


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    if i >= len(data):
        fail(E_TSA, "truncated DER length")
    first = data[i]
    i += 1
    if first < 128:
        return first, i
    n = first & 0x7F
    if n == 0 or n > 4 or i + n > len(data):
        fail(E_TSA, "invalid DER length")
    raw = data[i : i + n]
    if raw[0] == 0:
        fail(E_TSA, "non-minimal DER length")
    value = int.from_bytes(raw, "big")
    if value < 128:
        fail(E_TSA, "non-minimal DER length")
    return value, i + n


def parse_tlv(data: bytes, i: int = 0) -> tuple[int, bytes, int]:
    if i >= len(data):
        fail(E_TSA, "truncated DER tag")
    tag = data[i]
    length, j = _read_len(data, i + 1)
    end = j + length
    if end > len(data) or end < j:
        fail(E_TSA, "truncated DER value")
    return tag, data[j:end], end


def parse_tlv_raw(data: bytes, i: int = 0) -> tuple[bytes, int]:
    _tag, _body, end = parse_tlv(data, i)
    return data[i:end], end


def parse_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in body[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


@dataclass(frozen=True)
class TimeStampToken:
    der: bytes
    gen_time: dt.datetime
    message_imprint: str
    serial: int

    def b64(self) -> str:
        return base64.b64encode(self.der).decode("ascii")


def build_tst_info(imprint_hex: str, serial: int, when: dt.datetime) -> bytes:
    hashed = bytes.fromhex(imprint_hex)
    alg = der_seq(der_oid(OID_SHA256), der_null())
    imprint = der_seq(alg, der_octets(hashed))
    return der_seq(
        der_int(1),
        der_oid(OID_BEACON_POLICY),
        imprint,
        der_int(serial),
        der_gentime(when),
    )


def _algorithm_identifier(oid: bytes) -> bytes:
    return der_seq(der_oid(oid), der_null())


def wrap_signed_data(tst_info: bytes, cert_der: bytes, signature: bytes) -> bytes:
    """CMS SignedData ContentInfo with eContentType id-ct-TSTInfo (RFC 3161)."""
    encap = der_seq(
        der_oid(OID_TST_INFO),
        der_explicit(0, der_octets(tst_info)),
    )
    digest_algs = der_set(_algorithm_identifier(OID_SHA256))
    certs = der_implicit_set(0, cert_der)
    signer_info = der_seq(
        der_int(1),
        der_seq(der_int(0), der_int(1)),  # IssuerAndSerialNumber placeholder; verify uses embedded cert
        _algorithm_identifier(OID_SHA256),
        _algorithm_identifier(OID_RSA_ENC),
        der_octets(signature),
    )
    signed_data = der_seq(
        der_int(3),
        digest_algs,
        encap,
        certs,
        der_set(signer_info),
    )
    return der_seq(der_oid(OID_SIGNED_DATA), der_explicit(0, signed_data))


def generate_tsa(keys_dir: Path) -> x509.Certificate:
    keys_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Beacon Local TSA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Beacon"),
        ]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (keys_dir / TSA_KEY).write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (keys_dir / TSA_KEY).chmod(0o600)
    (keys_dir / TSA_CERT).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _load_tsa_key(keys_dir: Path) -> rsa.RSAPrivateKey:
    path = keys_dir / TSA_KEY
    if not path.exists():
        fail(E_TSA, "missing TSA key; run `beacon init`")
    loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        fail(E_TSA, "TSA key is not RSA")
    return loaded


def _load_tsa_cert(keys_dir: Path) -> x509.Certificate:
    path = keys_dir / TSA_CERT
    if not path.exists():
        fail(E_TSA, "missing TSA certificate; run `beacon init`")
    return x509.load_pem_x509_certificate(path.read_bytes())


def stamp_local(keys_dir: Path, imprint_hex: str, serial: int) -> TimeStampToken:
    when = dt.datetime.now(dt.timezone.utc)
    tst_info = build_tst_info(imprint_hex, serial, when)
    key = _load_tsa_key(keys_dir)
    cert = _load_tsa_cert(keys_dir)
    signature = key.sign(tst_info, padding.PKCS1v15(), hashes.SHA256())
    der = wrap_signed_data(tst_info, cert.public_bytes(serialization.Encoding.DER), signature)
    return TimeStampToken(der=der, gen_time=when, message_imprint=imprint_hex, serial=serial)


def _der_children(body: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    i = 0
    while i < len(body):
        tag, part, nxt = parse_tlv(body, i)
        if nxt <= i:
            fail(E_TSA, "DER parse did not advance")
        items.append((tag, part))
        i = nxt
    return items


def parse_timestamp_token(der: bytes) -> tuple[bytes, bytes]:
    """Return (TSTInfo DER, RSA signature) from a CMS TimeStampToken."""
    tag, content_info, _ = parse_tlv(der, 0)
    if tag != 0x30:
        fail(E_TSA, "TimeStampToken is not a SEQUENCE")
    kids = _der_children(content_info)
    if len(kids) < 2 or kids[1][0] != 0xA0:
        fail(E_TSA, "TimeStampToken missing SignedData")
    inner_tag, signed_seq, _ = parse_tlv(kids[1][1], 0)
    if inner_tag != 0x30:
        fail(E_TSA, "SignedData is not a SEQUENCE")
    signed = _der_children(signed_seq)
    if len(signed) < 5:
        fail(E_TSA, "SignedData missing encapContentInfo or signerInfos")
    encap = _der_children(signed[2][1])
    tst_info: bytes | None = None
    for etag, ebody in encap:
        if etag != 0xA0:
            continue
        otag, octets, _ = parse_tlv(ebody, 0)
        if otag != 0x04:
            fail(E_TSA, "eContent is not OCTET STRING")
        tst_info = octets
    if tst_info is None:
        fail(E_TSA, "TimeStampToken missing TSTInfo")
    signer_tag, signer_body = signed[-1]
    if signer_tag != 0x31:
        fail(E_TSA, "signerInfos is not a SET")
    sitag, si_body, _ = parse_tlv(signer_body, 0)
    if sitag != 0x30:
        fail(E_TSA, "SignerInfo is not a SEQUENCE")
    signature: bytes | None = None
    for field_tag, field_body in _der_children(si_body):
        if field_tag == 0x04:
            signature = field_body
    if not signature:
        fail(E_TSA, "SignerInfo missing signature OCTET STRING")
    return tst_info, signature


def _find_tst_info(der: bytes) -> bytes:
    tst_info, _sig = parse_timestamp_token(der)
    return tst_info


def parse_tst_info(tst_info: bytes) -> tuple[str, int, dt.datetime]:
    tag, seq, _ = parse_tlv(tst_info, 0)
    if tag != 0x30:
        fail(E_TSA, "TSTInfo is not a SEQUENCE")
    i = 0
    _, _, i = parse_tlv(seq, i)  # version
    _, _, i = parse_tlv(seq, i)  # policy
    _, imprint_body, i = parse_tlv(seq, i)
    _, serial_body, i = parse_tlv(seq, i)
    _, time_body, i = parse_tlv(seq, i)
    # imprint = alg + hashed_message
    j = 0
    _, _, j = parse_tlv(imprint_body, j)
    _, hashed, j = parse_tlv(imprint_body, j)
    serial = int.from_bytes(serial_body, "big")
    when = dt.datetime.strptime(time_body.decode("ascii"), "%Y%m%d%H%M%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    return hashed.hex(), serial, when


def verify_token(der: bytes, expected_imprint: str, cert_pem: bytes) -> TimeStampToken:
    tst_info = _find_tst_info(der)
    imprint, serial, when = parse_tst_info(tst_info)
    if imprint != expected_imprint:
        fail(E_TSA, "TSA messageImprint does not match Merkle root")
    cert = x509.load_pem_x509_certificate(cert_pem)
    public = cert.public_key()
    if not isinstance(public, rsa.RSAPublicKey):
        fail(E_TSA, "TSA certificate is not RSA")
    _info, sig = parse_timestamp_token(der)
    try:
        public.verify(sig, tst_info, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        fail(E_TSA, f"TSA signature verify failed: {exc}")
    return TimeStampToken(der=der, gen_time=when, message_imprint=imprint, serial=serial)


def stamp_remote(tsa_url: str, imprint_hex: str) -> bytes:
    """POST a TimeStampReq (RFC 3161) and return the TimeStampToken DER."""
    hashed = bytes.fromhex(imprint_hex)
    alg = der_seq(der_oid(OID_SHA256), der_null())
    imprint = der_seq(alg, der_octets(hashed))
    req = der_seq(der_int(1), imprint)
    try:
        response = httpx.post(
            tsa_url,
            content=req,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=20.0,
        )
        response.raise_for_status()
    except Exception as exc:
        fail(E_TSA, f"remote TSA request failed: {exc}")
    # TimeStampResp = SEQUENCE { status, timeStampToken OPTIONAL }
    tag, body, _ = parse_tlv(response.content, 0)
    if tag != 0x30:
        fail(E_TSA, "remote TSA response is not a SEQUENCE")
    i = 0
    _, _, i = parse_tlv(body, i)  # PKIStatusInfo
    if i >= len(body):
        fail(E_TSA, "remote TSA returned no TimeStampToken")
    token_der, _end = parse_tlv_raw(body, i)
    return token_der


def stamp(keys_dir: Path, imprint_hex: str, serial: int, tsa_url: str | None) -> TimeStampToken:
    if tsa_url:
        der = stamp_remote(tsa_url, imprint_hex)
        cert_path = keys_dir / TSA_CERT
        if not cert_path.exists():
            fail(E_TSA, "no TSA trust anchor; run `beacon init`")
        return verify_token(der, imprint_hex, cert_path.read_bytes())
    return stamp_local(keys_dir, imprint_hex, serial)
