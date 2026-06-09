"""
SAML 2.0 IdP endpoints.

/saml/metadata   — IdP metadata XML (download and register in each SP)
/saml/sso        — Single Sign-On service (GET = redirect binding, POST = POST binding)
/saml/login      — Login page shown during SSO if no active SSO session
/saml/sls        — Single Logout Service
/saml/idp-info   — Human-readable IdP configuration page (admin only)
"""
import uuid

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..database import get_db
from ..models.sp import ServiceProvider
from ..models.user import User
from ..services.auth import (
    create_sso_token,
    decode_access_token,
    decode_sso_token,
    verify_password,
)
from ..services.saml_idp import (
    build_saml_response,
    get_cert_b64,
    idp_metadata_xml,
    parse_authn_request,
)

router = APIRouter(prefix="/saml", tags=["saml"])
templates = Jinja2Templates(directory="app/templates")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_sso_user(request: Request, db: Session) -> User | None:
    token = request.cookies.get("sso_session")
    if not token:
        return None
    user_id = decode_sso_token(token)
    if not user_id:
        return None
    try:
        return db.query(User).options(selectinload(User.groups)).filter(
            User.id == uuid.UUID(user_id), User.is_active == True  # noqa: E712
        ).first()
    except ValueError:
        return None


def _get_sp(entity_id: str, db: Session) -> ServiceProvider | None:
    return db.query(ServiceProvider).filter(
        ServiceProvider.entity_id == entity_id,
        ServiceProvider.is_active == True,  # noqa: E712
    ).first()


def _sso_response(user: User, sp: ServiceProvider, in_response_to: str, relay_state: str):
    """Build the auto-submitting form that POSTs the SAML response to the SP."""
    acs_url, response_b64, rs = build_saml_response(user, sp, in_response_to, relay_state)
    return templates.TemplateResponse("saml_form_post.html", {
        "request": None,  # form_post template doesn't use request
        "acs_url": acs_url,
        "saml_response": response_b64,
        "relay_state": rs,
        "sp_name": sp.name,
    })


# ── Metadata ──────────────────────────────────────────────────────────────────

@router.get("/metadata")
def metadata():
    xml = idp_metadata_xml()
    return Response(content=xml, media_type="application/samlmetadata+xml")


# ── SSO ───────────────────────────────────────────────────────────────────────

@router.get("/sso")
def sso_redirect(
    request: Request,
    db: Session = Depends(get_db),
    SAMLRequest: str = "",
    RelayState: str = "",
):
    if not SAMLRequest:
        return HTMLResponse("<h3>Missing SAMLRequest parameter</h3>", status_code=400)

    try:
        authn = parse_authn_request(SAMLRequest, binding="redirect")
    except Exception as e:
        return HTMLResponse(f"<h3>Invalid SAMLRequest: {e}</h3>", status_code=400)

    # Look up the SP by issuer entity ID
    sp = _get_sp(authn["issuer"], db)
    if not sp:
        return HTMLResponse(
            f"<h3>Unknown or inactive SP: {authn['issuer']}</h3>"
            "<p>Register this SP under Service Providers in the IAM admin UI.</p>",
            status_code=403,
        )

    # Check for existing SSO session
    user = _get_sso_user(request, db)
    if user:
        return _sso_response(user, sp, authn["id"], RelayState)

    # No session — redirect to SSO login page
    return RedirectResponse(
        f"/saml/login?SAMLRequest={SAMLRequest}&RelayState={RelayState}",
        status_code=302,
    )


@router.post("/sso")
async def sso_post(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    SAMLRequest = form.get("SAMLRequest", "")
    RelayState = form.get("RelayState", "")

    if not SAMLRequest:
        return HTMLResponse("<h3>Missing SAMLRequest</h3>", status_code=400)

    try:
        authn = parse_authn_request(SAMLRequest, binding="post")
    except Exception as e:
        return HTMLResponse(f"<h3>Invalid SAMLRequest: {e}</h3>", status_code=400)

    sp = _get_sp(authn["issuer"], db)
    if not sp:
        return HTMLResponse(f"<h3>Unknown SP: {authn['issuer']}</h3>", status_code=403)

    user = _get_sso_user(request, db)
    if user:
        return _sso_response(user, sp, authn["id"], RelayState)

    return RedirectResponse(
        f"/saml/login?SAMLRequest={SAMLRequest}&RelayState={RelayState}",
        status_code=302,
    )


# ── SSO Login ─────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
def sso_login_page(
    request: Request,
    SAMLRequest: str = "",
    RelayState: str = "",
    error: str = "",
):
    return templates.TemplateResponse("sso_login.html", {
        "request": request,
        "saml_request": SAMLRequest,
        "relay_state": RelayState,
        "error": error,
        "org_name": settings.idp_entity_id,
    })


@router.post("/login")
def sso_login(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...),
    saml_request: str = Form(""),
    relay_state: str = Form(""),
):
    user = db.query(User).options(selectinload(User.groups)).filter(
        User.email == email, User.is_active == True  # noqa: E712
    ).first()

    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return RedirectResponse(
            f"/saml/login?SAMLRequest={saml_request}&RelayState={relay_state}&error=Invalid+credentials",
            status_code=302,
        )

    # Build SAML response
    try:
        authn = parse_authn_request(saml_request, binding="redirect")
    except Exception:
        try:
            authn = parse_authn_request(saml_request, binding="post")
        except Exception as e:
            return HTMLResponse(f"<h3>Could not parse SAMLRequest: {e}</h3>", status_code=400)

    sp = _get_sp(authn["issuer"], db)
    if not sp:
        return HTMLResponse(f"<h3>Unknown SP: {authn['issuer']}</h3>", status_code=403)

    acs_url, response_b64, rs = build_saml_response(user, sp, authn["id"], relay_state)

    # Set SSO session cookie and return auto-submit form
    sso_token = create_sso_token(str(user.id))
    resp = templates.TemplateResponse("saml_form_post.html", {
        "request": request,
        "acs_url": acs_url,
        "saml_response": response_b64,
        "relay_state": rs,
        "sp_name": sp.name,
    })
    resp.set_cookie(
        "sso_session",
        sso_token,
        httponly=True,
        samesite="lax",
        max_age=settings.sso_session_expire_hours * 3600,
    )
    return resp


# ── Single Logout ─────────────────────────────────────────────────────────────

@router.post("/sls")
def single_logout(request: Request):
    response = HTMLResponse("""
    <!DOCTYPE html><html><head><title>Logged Out</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body class="d-flex align-items-center justify-content-center" style="min-height:100vh;background:#f4f6fb">
    <div class="text-center">
      <h4 class="fw-bold mb-2">You have been signed out</h4>
      <p class="text-muted">Your SSO session has ended.</p>
    </div></body></html>
    """)
    response.delete_cookie("sso_session")
    return response


@router.get("/sls")
def single_logout_get(request: Request):
    response = RedirectResponse("/saml/sls", status_code=307)
    return response


# ── IdP Info (admin) ──────────────────────────────────────────────────────────

@router.get("/idp-info", response_class=HTMLResponse)
def idp_info(request: Request, db: Session = Depends(get_db)):
    # Require admin session
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse("/ui/login", status_code=302)
    payload = decode_access_token(token)
    if not payload:
        return RedirectResponse("/ui/login", status_code=302)
    admin = db.query(User).filter(User.id == uuid.UUID(payload["sub"])).first()
    if not admin or not admin.is_admin:
        return RedirectResponse("/ui/login", status_code=302)

    base = settings.idp_base_url.rstrip("/")
    try:
        cert_b64 = get_cert_b64()
        # Fingerprint: SHA-256 of the DER cert
        from cryptography.hazmat.primitives import hashes as ch
        from cryptography.x509 import load_pem_x509_certificate
        from pathlib import Path
        cert_pem = Path(settings.saml_cert_file).read_bytes()
        cert_obj = load_pem_x509_certificate(cert_pem)
        fp = cert_obj.fingerprint(ch.SHA256()).hex()
        fingerprint = ":".join(fp[i:i+2].upper() for i in range(0, len(fp), 2))
        cert_valid_until = cert_obj.not_valid_after_utc
    except Exception:
        cert_b64 = ""
        fingerprint = "Keys not yet generated — start the server to generate"
        cert_valid_until = None

    return templates.TemplateResponse("idp_info.html", {
        "request": request,
        "current_user": admin,
        "active": "sps",
        "entity_id": settings.idp_entity_id,
        "sso_url": f"{base}/saml/sso",
        "sls_url": f"{base}/saml/sls",
        "metadata_url": f"{base}/saml/metadata",
        "cert_b64": cert_b64,
        "fingerprint": fingerprint,
        "cert_valid_until": cert_valid_until,
    })
