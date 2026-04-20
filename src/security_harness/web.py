from pathlib import Path

import markdown as md
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from security_harness.live_state import LiveState
from security_harness.state import State

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _md(text: str) -> Markup:
    return Markup(md.markdown(text or "", extensions=["fenced_code", "tables"]))


def create_app(state: State, live: LiveState) -> FastAPI:
    app = FastAPI(title="Security Harness")
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    templates.env.filters["markdown"] = _md

    def _worker_ctx() -> dict:
        snap = live.snapshot()
        return {
            "analysis_workers": snap["analysis_workers"],
            "verify_workers": snap["verify_workers"],
        }

    def _active_ctx() -> dict:
        snap = live.snapshot()
        return {
            "analysis_active": snap["analysis_active"],
            "verify_active": snap["verify_active"],
        }

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        files = state.get_file_rankings()
        bugs = state.get_bug_reports_with_repro()
        reproduced = state.get_reproduced_bugs()
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "files": files,
                "bugs": bugs,
                "reproduced": reproduced,
                **_worker_ctx(),
                **_active_ctx(),
            },
        )

    @app.get("/partials/workers", response_class=HTMLResponse)
    async def partial_workers(request: Request):
        return templates.TemplateResponse(
            request,
            "partials/workers.html",
            _worker_ctx(),
        )

    @app.get("/partials/active", response_class=HTMLResponse)
    async def partial_active(request: Request):
        return templates.TemplateResponse(
            request,
            "partials/active.html",
            _active_ctx(),
        )

    @app.get("/partials/files", response_class=HTMLResponse)
    async def partial_files(request: Request):
        files = state.get_file_rankings()
        return templates.TemplateResponse(
            request,
            "partials/files.html",
            {"files": files},
        )

    @app.get("/partials/bugs", response_class=HTMLResponse)
    async def partial_bugs(request: Request):
        bugs = state.get_bug_reports_with_repro()
        return templates.TemplateResponse(
            request,
            "partials/bugs.html",
            {"bugs": bugs},
        )

    @app.get("/partials/reproduced", response_class=HTMLResponse)
    async def partial_reproduced(request: Request):
        bugs = state.get_reproduced_bugs()
        return templates.TemplateResponse(
            request,
            "partials/reproduced.html",
            {"bugs": bugs},
        )

    @app.get("/repro/{attempt_id}", response_class=HTMLResponse)
    async def repro_detail(request: Request, attempt_id: int):
        bug = state.get_repro_detail(attempt_id)
        if bug is None:
            raise HTTPException(status_code=404, detail="Not found")
        return templates.TemplateResponse(request, "repro_detail.html", {"bug": bug})

    @app.post("/bugs/{bug_id}/invalid", response_class=HTMLResponse)
    async def bug_mark_invalid(request: Request, bug_id: int, reason: str = Form("")):
        state.mark_bug_invalid(bug_id, reason)
        if request.headers.get("HX-Request"):
            bugs = state.get_bug_reports_with_repro()
            return templates.TemplateResponse(request, "partials/bugs.html", {"bugs": bugs})
        return RedirectResponse(request.headers.get("referer", "/"), status_code=303)

    @app.post("/bugs/{bug_id}/valid", response_class=HTMLResponse)
    async def bug_mark_valid(request: Request, bug_id: int):
        state.mark_bug_valid(bug_id)
        if request.headers.get("HX-Request"):
            bugs = state.get_bug_reports_with_repro()
            return templates.TemplateResponse(request, "partials/bugs.html", {"bugs": bugs})
        return RedirectResponse(request.headers.get("referer", "/"), status_code=303)

    @app.post("/repro/{attempt_id}/invalid")
    async def attempt_mark_invalid(attempt_id: int, reason: str = Form("")):
        state.mark_attempt_invalid(attempt_id, reason)
        return RedirectResponse(f"/repro/{attempt_id}", status_code=303)

    @app.post("/repro/{attempt_id}/valid")
    async def attempt_mark_valid(attempt_id: int):
        state.mark_attempt_valid(attempt_id)
        return RedirectResponse(f"/repro/{attempt_id}", status_code=303)

    return app
