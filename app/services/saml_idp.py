"""
SAML 2.0 Identity Provider service.

Handles:
- RSA key pair + self-signed cert generation (persisted to keys/ dir)
- IdP metadata XML generation
- AuthnRequest parsing (redirect + POST bindings)
- Signed SAML Response + Assertion generation
"""
import base64
import os
import zlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from ..config import settings

# ── SAML Namespaces ───────────────────────────────────────────────────────────
NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xs": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}

SAML = NS["saml"]
SAMLP = NS["samlp"]
MD = NS["md"]
DS = NS["ds"]
XSI = NS["xsi"]

NAME_ID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Key management ────────────────────────────────────────────────────────────

def ensure_saml_keys() -> tuple[bytes, bytes]:
    """Return (key_pem, cert_pem), generating and saving on first call."""
    key_path = Path(settings.saml_key_file)
    cert_path = Path(settings.saml_cert_file)

    if key_path.exists() and cert_path.exists():
        return key_path.read_bytes(), cert_path.read_bytes()

    key_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = settings.idp_entity_id.replace("https://", "").replace("http://", "")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Netskope IAM"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    key_path.write_bytes(key_pem)
    cert_path.write_bytes(cert_pem)

    # Restrict key file permissions on Unix
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

    return key_pem, cert_pem


def get_cert_b64() -> str:
    """Return the signing cert as bare Base64 DER (for embedding in metadata/UI)."""
    _, cert_pem = ensure_saml_keys()
    from cryptography.x509 import load_pem_x509_certificate
    cert = load_pem_x509_certificate(cert_pem)
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


# ── Metadata ──────────────────────────────────────────────────────────────────

def idp_metadata_xml() -> str:
    base = settings.idp_base_url.rstrip("/")
    cert_b64 = get_cert_b64()

    root = etree.Element(f"{{{MD}}}EntityDescriptor", nsmap={"md": MD, "ds": DS})
    root.set("entityID", settings.idp_entity_id)

    idp_sso = etree.SubElement(root, f"{{{MD}}}IDPSSODescriptor")
    idp_sso.set("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
    idp_sso.set("WantAuthnRequestsSigned", "false")

    # Signing key descriptor
    key_desc = etree.SubElement(idp_sso, f"{{{MD}}}KeyDescriptor")
    key_desc.set("use", "signing")
    key_info = etree.SubElement(key_desc, f"{{{DS}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{DS}}}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{{{DS}}}X509Certificate")
    x509_cert.text = cert_b64

    # SLO endpoint
    slo = etree.SubElement(idp_sso, f"{{{MD}}}SingleLogoutService")
    slo.set("Binding", BINDING_POST)
    slo.set("Location", f"{base}/saml/sls")

    # SSO endpoints
    for binding in (BINDING_REDIRECT, BINDING_POST):
        sso_el = etree.SubElement(idp_sso, f"{{{MD}}}SingleSignOnService")
        sso_el.set("Binding", binding)
        sso_el.set("Location", f"{base}/saml/sso")

    return etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8").decode()


# ── AuthnRequest parsing ──────────────────────────────────────────────────────

def parse_authn_request(saml_request: str, binding: str = "redirect") -> dict:
    """
    Decode and parse an AuthnRequest.
    binding: 'redirect' (deflate+base64) or 'post' (base64 only)
    """
    raw = base64.b64decode(saml_request)
    if binding == "redirect":
        raw = zlib.decompress(raw, -15)  # raw deflate (no header)

    root = etree.fromstring(raw)
    issuer_el = root.find(f"{{{SAML}}}Issuer")
    name_id_policy = root.find(f"{{{SAMLP}}}NameIDPolicy")

    return {
        "id": root.get("ID", ""),
        "issuer": issuer_el.text.strip() if issuer_el is not None else "",
        "acs_url": root.get("AssertionConsumerServiceURL", ""),
        "destination": root.get("Destination", ""),
        "name_id_format": (
            name_id_policy.get("Format", NAME_ID_EMAIL)
            if name_id_policy is not None
            else NAME_ID_EMAIL
        ),
    }


# ── Assertion + Response generation ──────────────────────────────────────────

def _build_assertion(user, sp, assertion_id: str, in_response_to: str, now: datetime) -> etree.Element:
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(minutes=10)
    session_expires = now + timedelta(hours=settings.sso_session_expire_hours)

    nsmap = {"saml": SAML}
    assertion = etree.Element(f"{{{SAML}}}Assertion", nsmap=nsmap)
    assertion.set("Version", "2.0")
    assertion.set("ID", assertion_id)
    assertion.set("IssueInstant", _fmt(now))

    issuer = etree.SubElement(assertion, f"{{{SAML}}}Issuer")
    issuer.text = settings.idp_entity_id

    # Subject
    subject = etree.SubElement(assertion, f"{{{SAML}}}Subject")
    name_id = etree.SubElement(subject, f"{{{SAML}}}NameID")
    name_id.set("Format", sp.name_id_format or NAME_ID_EMAIL)
    name_id.text = user.email

    sub_confirm = etree.SubElement(subject, f"{{{SAML}}}SubjectConfirmation")
    sub_confirm.set("Method", CM_BEARER)
    scd = etree.SubElement(sub_confirm, f"{{{SAML}}}SubjectConfirmationData")
    scd.set("NotOnOrAfter", _fmt(not_after))
    scd.set("Recipient", sp.acs_url)
    if in_response_to:
        scd.set("InResponseTo", in_response_to)

    # Conditions
    conditions = etree.SubElement(assertion, f"{{{SAML}}}Conditions")
    conditions.set("NotBefore", _fmt(not_before))
    conditions.set("NotOnOrAfter", _fmt(not_after))
    aud_restr = etree.SubElement(conditions, f"{{{SAML}}}AudienceRestriction")
    audience = etree.SubElement(aud_restr, f"{{{SAML}}}Audience")
    audience.text = sp.entity_id

    # AuthnStatement
    authn_stmt = etree.SubElement(assertion, f"{{{SAML}}}AuthnStatement")
    authn_stmt.set("AuthnInstant", _fmt(now))
    authn_stmt.set("SessionNotOnOrAfter", _fmt(session_expires))
    authn_stmt.set("SessionIndex", f"_{uuid4().hex}")
    authn_ctx = etree.SubElement(authn_stmt, f"{{{SAML}}}AuthnContext")
    authn_ctx_class = etree.SubElement(authn_ctx, f"{{{SAML}}}AuthnContextClassRef")
    authn_ctx_class.text = AC_PASSWORD

    # AttributeStatement
    attr_stmt = etree.SubElement(assertion, f"{{{SAML}}}AttributeStatement")

    def add_attr(name: str, value: str) -> None:
        attr = etree.SubElement(attr_stmt, f"{{{SAML}}}Attribute")
        attr.set("Name", name)
        attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        val_el = etree.SubElement(attr, f"{{{SAML}}}AttributeValue")
        val_el.set(f"{{{XSI}}}type", "xs:string")
        val_el.text = value

    add_attr("email", user.email)
    add_attr("firstName", user.given_name or "")
    add_attr("lastName", user.family_name or "")
    add_attr("displayName", user.display_name or user.email)

    # Multi-value groups attribute
    if user.groups:
        attr = etree.SubElement(attr_stmt, f"{{{SAML}}}Attribute")
        attr.set("Name", "groups")
        attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
        for group in user.groups:
            val_el = etree.SubElement(attr, f"{{{SAML}}}AttributeValue")
            val_el.set(f"{{{XSI}}}type", "xs:string")
            val_el.text = group.display_name

    return assertion


def _sign_element(element: etree.Element) -> etree.Element:
    key_pem, cert_pem = ensure_saml_keys()
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    return signer.sign(element, key=key_pem, cert=cert_pem)


def build_saml_response(user, sp, in_response_to: str = "", relay_state: str = "") -> tuple[str, str, str]:
    """
    Build, sign, and encode a SAML Response.
    Returns: (acs_url, base64_encoded_response, relay_state)
    """
    now = datetime.utcnow()
    assertion_id = f"_{uuid4().hex}"
    response_id = f"_{uuid4().hex}"

    # Build and sign the assertion
    assertion = _build_assertion(user, sp, assertion_id, in_response_to, now)
    signed_assertion = _sign_element(assertion)

    # Build the Response envelope
    nsmap = {"samlp": SAMLP, "saml": SAML}
    response = etree.Element(f"{{{SAMLP}}}Response", nsmap=nsmap)
    response.set("Version", "2.0")
    response.set("ID", response_id)
    response.set("IssueInstant", _fmt(now))
    response.set("Destination", sp.acs_url)
    if in_response_to:
        response.set("InResponseTo", in_response_to)

    issuer = etree.SubElement(response, f"{{{SAML}}}Issuer")
    issuer.text = settings.idp_entity_id

    status = etree.SubElement(response, f"{{{SAMLP}}}Status")
    status_code = etree.SubElement(status, f"{{{SAMLP}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    response.append(signed_assertion)

    xml_bytes = etree.tostring(response, encoding="UTF-8", xml_declaration=True)
    response_b64 = base64.b64encode(xml_bytes).decode()

    return sp.acs_url, response_b64, relay_state
