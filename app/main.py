from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .database import engine, Base
from .models import user, group  # noqa: F401 — registers tables with Base
from .routers import ui, api, scim, saml
from .services.saml_idp import ensure_saml_keys

Base.metadata.create_all(bind=engine)
ensure_saml_keys()  # generate SAML key pair on first start if missing

app = FastAPI(title="Netskope IAM Server", docs_url="/api/docs", redoc_url=None)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(ui.router)
app.include_router(api.router)
app.include_router(scim.router)
app.include_router(saml.router)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/dashboard", status_code=302)
