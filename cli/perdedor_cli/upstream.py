"""`perdedor upstream` and `perdedor coverage`: keep Perdedor current with the projects it mirrors.

perdedor upstream check [--state FILE] [--json] [--offline] [--token-env VAR]
perdedor upstream status [--state FILE] [--json]
perdedor upstream pin ID... | --all [--inventory]        # after reviewing an update
perdedor upstream refresh [ID...] [--at pinned|latest]    # rebuild catalog/inventory/*.json
perdedor coverage [--tool NAME] [--json | --markdown]

`check` asks GitHub (and a few web pages) for the newest release, tag or commit of every source in
catalog/upstreams.json, compares it with the pinned revision and with the state file, and for every source
that moved re-runs its parser on the new revision to list upstream techniques that no catalog check maps.
Exit codes: 0 nothing new, 10 updates available, 1 error. Only the standard library is used.

`coverage` joins the committed inventories (catalog/inventory/*.json) with the ``equivalents`` of the check
catalog and reports, per upstream project, which techniques are covered, planned, not feasible or missing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from perdedor_cli import inventory_parsers as parsers

EXIT_OK = 0
EXIT_UPDATES = 10
EXIT_ERROR = 1

STATE_FORMAT = 1
KINDS = ("github-release", "github-commits", "github-tag", "web-page", "attack-stix")
API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
USER_AGENT = "perdedor-upstream-watch (+https://github.com/Chimera-Co/perdedor)"
HTTP_TIMEOUT_S = 25.0  # per request
HTTP_RETRIES = 3  # extra attempts after the first
BACKOFF_BASE_S = 2.0  # 2, 4, 8 s
MAX_WAIT_S = 30.0  # longest Retry-After or rate-limit reset the tool sleeps through; beyond it, it gives up
MAX_BODY_BYTES = 64 * 1024 * 1024  # largest non-streamed response
MAX_CACHED_TEXT = 512 * 1024  # largest API response kept in the state file for If-None-Match
COMMIT_PATH_LIMIT = 12  # at most this many paths are queried for "newest commit touching a tracked path"
STATUS_PRIORITY = {"implemented": 3, "planned": 2, "not_feasible": 1}

# ------------------------------------------------------------------------------------------------ errors


class UpstreamError(Exception):
    """A failure that applies to one source (reported, then the run continues)."""


class HttpError(UpstreamError):
    def __init__(self, status: int, url: str, message: str = ""):
        super().__init__(f"HTTP {status} for {redact(url)}" + (f": {message}" if message else ""))
        self.status = status
        self.url = url


class RateLimited(HttpError):
    def __init__(self, url: str, reset_at: float | None):
        when = (
            dt.datetime.fromtimestamp(reset_at, dt.timezone.utc).strftime("%H:%M:%SZ")
            if reset_at
            else "later"
        )
        super().__init__(403, url, f"rate limited; limit resets at {when} (use --token-env to raise it)")
        self.reset_at = reset_at


def redact(text: str) -> str:
    """Drop query strings (they may carry parameters) from a URL shown in a message."""
    return text.split("?", 1)[0]


# --------------------------------------------------------------------------------------------- HTTP layer


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects (renamed repositories answer 301) and never carry the token to another host."""

    def __init__(self, token: str | None):
        self.token = token

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and self.token and urllib.parse.urlparse(newurl).hostname == "api.github.com":
            new.add_unredirected_header("Authorization", f"Bearer {self.token}")
        return new


class Http:
    """urllib with timeouts, retries with exponential backoff, rate-limit handling and conditional requests.

    Proxies come from the usual environment variables (HTTPS_PROXY, NO_PROXY, ...) because ``urllib``'s default
    opener reads them. The token, when given, is sent only to api.github.com."""

    def __init__(
        self,
        token: str | None = None,
        timeout: float = HTTP_TIMEOUT_S,
        retries: int = HTTP_RETRIES,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        opener: urllib.request.OpenerDirector | None = None,
    ):
        self._token = token
        self.timeout = timeout
        self.retries = retries
        self._sleep = sleep
        self._now = now
        self._opener = opener or urllib.request.build_opener(_Redirects(token))

    def _request(self, url: str, etag: str | None, accept: str | None) -> urllib.request.Request:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        req.add_header("Accept", accept or "*/*")
        if etag:
            req.add_header("If-None-Match", etag)
        if self._token and urllib.parse.urlparse(url).hostname == "api.github.com":
            req.add_unredirected_header("Authorization", f"Bearer {self._token}")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
        return req

    def _open(self, url: str, etag: str | None = None, accept: str | None = None):
        """Open ``url`` and return the response object (a 304 is returned as a ``Response``)."""
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                return self._opener.open(self._request(url, etag, accept), timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                if exc.code == 304:
                    return Response(304, {k.lower(): v for k, v in exc.headers.items()})
                if exc.code in (403, 429):
                    wait = self._rate_limit_wait(exc)
                    if wait is None:
                        raise HttpError(exc.code, url, exc.reason) from None
                    if wait > MAX_WAIT_S or attempt == self.retries:
                        reset = exc.headers.get("X-RateLimit-Reset")
                        raise RateLimited(url, float(reset) if reset else None) from None
                    self._sleep(wait)
                    continue
                if exc.code >= 500 and attempt < self.retries:
                    last = exc
                    self._sleep(BACKOFF_BASE_S * 2**attempt)
                    continue
                raise HttpError(exc.code, url, exc.reason) from None
            except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError) as exc:
                last = exc
                if attempt < self.retries:
                    self._sleep(BACKOFF_BASE_S * 2**attempt)
                    continue
        raise HttpError(0, url, f"network error: {getattr(last, 'reason', last)}")

    def _rate_limit_wait(self, exc: urllib.error.HTTPError) -> float | None:
        """Seconds to wait before retrying a 403/429, or None when the response is not a rate limit."""
        retry_after = exc.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return float(retry_after)
        if exc.headers.get("X-RateLimit-Remaining") == "0":
            reset = exc.headers.get("X-RateLimit-Reset")
            return max(0.0, float(reset) - self._now()) + 1.0 if reset else MAX_WAIT_S + 1
        return None

    def get(self, url: str, etag: str | None = None, accept: str | None = None) -> Response:
        resp = self._open(url, etag, accept)
        if isinstance(resp, Response):
            return resp
        with resp:
            body = resp.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise UpstreamError(f"response from {redact(url)} is larger than {MAX_BODY_BYTES} bytes")
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, body)

    def stream(self, url: str):
        """A binary file object for a large download (closed by the caller)."""
        resp = self._open(url)
        if isinstance(resp, Response):
            raise HttpError(resp.status, url, "unexpected conditional response")
        return resp


# --------------------------------------------------------------------------------------------- GitHub


def version_key(name: str) -> tuple:
    """Sort key for tags such as v2.8.2, xen-RELEASE-4.19.4 or ATT&CK-v20.1 (numbers compare as numbers)."""
    return tuple(int(n) for n in re.findall(r"\d+", name)), name


class GitHub:
    """The few GitHub REST and raw-content calls the watcher needs. ``cache`` is the state file's
    ``cache`` mapping: responses are stored with their ETag and revalidated with If-None-Match."""

    def __init__(self, http: Http, cache: dict | None = None):
        self.http = http
        self.cache = cache if cache is not None else {}

    def api(self, path: str) -> Any:
        url = f"{API}/{path}"
        entry = self.cache.get(url) or {}
        resp = self.http.get(url, etag=entry.get("etag"), accept="application/vnd.github+json")
        if resp.status == 304 and "text" in entry:
            return json.loads(entry["text"])
        text = resp.text
        etag = resp.headers.get("etag")
        if etag and len(text) <= MAX_CACHED_TEXT:
            self.cache[url] = {"etag": etag, "text": text}
        return json.loads(text)

    def latest_release(self, repo: str) -> dict | None:
        try:
            return self.api(f"repos/{repo}/releases/latest")
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise

    def tag_names(self, repo: str, prefix: str | None = None) -> list[str]:
        if prefix:
            refs = self.api(f"repos/{repo}/git/matching-refs/tags/{urllib.parse.quote(prefix)}")
            return [r["ref"].removeprefix("refs/tags/") for r in refs]
        return [t["name"] for t in self.api(f"repos/{repo}/tags?per_page=100")]

    def commit(self, repo: str, ref: str | None = None, path: str | None = None) -> dict | None:
        query = {"per_page": "1"}
        if ref:
            query["sha"] = ref
        if path:
            query["path"] = path.rstrip("/")
        rows = self.api(f"repos/{repo}/commits?{urllib.parse.urlencode(query)}")
        return rows[0] if rows else None

    def resolve(self, repo: str, ref: str) -> dict:
        return self.api(f"repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}")

    def tree(self, repo: str, ref: str) -> list[str]:
        doc = self.api(f"repos/{repo}/git/trees/{urllib.parse.quote(ref, safe='')}?recursive=1")
        if doc.get("truncated"):
            raise UpstreamError(f"file listing of {repo}@{ref} is truncated by GitHub")
        return [e["path"] for e in doc.get("tree", []) if e.get("type") == "blob"]

    @staticmethod
    def raw_url(repo: str, ref: str, path: str) -> str:
        return f"{RAW}/{repo}/{urllib.parse.quote(ref, safe='')}/{urllib.parse.quote(path)}"

    def raw(self, repo: str, ref: str, path: str) -> str:
        return self.http.get(self.raw_url(repo, ref, path)).text


# ---------------------------------------------------------------------------------- catalog and files


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if default is not None:
            return default
        raise UpstreamError(f"{path} does not exist") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise UpstreamError(f"cannot read {path}: {exc}") from None


def write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def catalog_dir(arg: str | None) -> Path:
    from perdedor_common.catalog import default_catalog_dir

    return Path(arg) if arg else default_catalog_dir()


def load_upstreams(cat: Path) -> list[dict]:
    return load_json(cat / "upstreams.json")["upstreams"]


def load_inventory(cat: Path, source_id: str) -> dict | None:
    path = cat / "inventory" / f"{source_id}.json"
    return load_json(path) if path.is_file() else None


def default_state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "perdedor" / "upstream-state.json"


def load_state(path: Path) -> dict:
    state = load_json(path, default={}) if path.exists() else {}
    state.setdefault("format", STATE_FORMAT)
    state.setdefault("cache", {})
    state.setdefault("seen", {})
    return state


def validate_upstreams(upstreams: list[dict], cat: Path) -> list[str]:
    """Problems with catalog/upstreams.json and its inventories (empty list when it is sound)."""
    problems: list[str] = []
    ids: set[str] = set()
    for i, s in enumerate(upstreams):
        sid = s.get("id", f"#{i}")
        for key in ("id", "name", "kind", "url", "paths", "parser", "why", "pinned"):
            if key not in s:
                problems.append(f"{sid}: missing '{key}'")
        if sid in ids:
            problems.append(f"{sid}: duplicate id")
        ids.add(sid)
        if s.get("kind") not in KINDS:
            problems.append(f"{sid}: unknown kind {s.get('kind')!r}")
        if s.get("kind") != "web-page" and not re.fullmatch(r"[\w.-]+/[\w.-]+", s.get("repo", "")):
            problems.append(f"{sid}: 'repo' must be owner/name")
        parser = s.get("parser")
        if parser not in parsers.TEXT_PARSERS and parser not in parsers.STIX_PARSERS:
            problems.append(f"{sid}: unknown parser {parser!r}")
        pinned = s.get("pinned") or {}
        if not pinned.get("version") or not pinned.get("date"):
            problems.append(f"{sid}: pinned needs version and date")
        if parser not in (None, "none") and not (cat / "inventory" / f"{sid}.json").is_file():
            problems.append(f"{sid}: parser {parser} but catalog/inventory/{sid}.json is missing")
    for path in sorted((cat / "inventory").glob("*.json")) if (cat / "inventory").is_dir() else []:
        if path.stem not in ids:
            problems.append(f"inventory/{path.name}: no source with that id")
    return problems


# ----------------------------------------------------------------------------------------- coverage


@dataclass
class Mapper:
    """Looks upstream technique names up in the check catalog."""

    checks: list[dict]
    techniques: dict[str, dict]
    _by_key: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)

    @classmethod
    def from_catalog(cls, cat: Path) -> "Mapper":
        from perdedor_common.catalog import load_catalog

        loaded = load_catalog(cat, cache=False)
        return cls(list(loaded.checks.values()), loaded.techniques)

    def patterns(self, key: str) -> list[tuple[str, str, str]]:
        """(pattern, status, check id) for every ``equivalents[key]`` pattern in the catalog."""
        if key not in self._by_key:
            rows = []
            for chk in self.checks:
                for pat in (chk.get("equivalents") or {}).get(key, []):
                    rows.append((pat, chk.get("status", "implemented"), chk["id"]))
            self._by_key[key] = rows
        return self._by_key[key]

    def lookup_tool(self, key: str, name: str) -> tuple[str, list[str]]:
        best, ids = "missing", []
        for pat, status, cid in self.patterns(key):
            if parsers.glob_match(pat, name):
                if STATUS_PRIORITY.get(status, 0) > STATUS_PRIORITY.get(best, 0):
                    best, ids = status, [cid]
                elif status == best:
                    ids.append(cid)
        return best, sorted(set(ids))

    def lookup_taxonomy(self, field_name: str, ident: str) -> tuple[str, list[str]]:
        """ATT&CK ('attack') and MBC ('mbc') ids reach checks through the technique they implement."""
        best, ids = "missing", []
        for chk in self.checks:
            tech = self.techniques.get(chk.get("technique", ""), {})
            if ident in tech.get(field_name, []):
                status = chk.get("status", "implemented")
                if STATUS_PRIORITY.get(status, 0) > STATUS_PRIORITY.get(best, 0):
                    best, ids = status, [chk["id"]]
                elif status == best:
                    ids.append(chk["id"])
        return best, sorted(set(ids))


def match_mode(source: Mapping) -> str:
    return {"attack_techniques": "attack", "mbc": "mbc"}.get(source.get("parser", ""), "equivalents")


def tool_key(source: Mapping) -> str:
    return source.get("equivalents_key") or source["id"]


def classify(source: Mapping, items: list[dict], mapper: Mapper) -> list[dict]:
    """Coverage status of each inventory item: covered | planned | not_feasible | missing."""
    mode = match_mode(source)
    key = tool_key(source)
    rows: list[dict] = []
    for it in items:
        if mode == "equivalents":
            status, ids = mapper.lookup_tool(key, it["name"])
        else:
            status, ids = mapper.lookup_taxonomy(mode, it["name"])
        rows.append({"name": it["name"], "detail": it.get("detail", ""), "status": status, "checks": ids})
    if mode in ("attack", "mbc"):  # a parent technique is covered when one of its sub-techniques is
        by_name = {r["name"]: r for r in rows}
        for r in rows:
            if r["status"] in ("missing", "planned", "not_feasible") and "." not in r["name"]:
                kids = [k for n, k in by_name.items() if n.startswith(r["name"] + ".")]
                if any(k["status"] == "implemented" for k in kids):
                    r["status"] = "implemented"
                    r["checks"] = sorted({c for k in kids for c in k["checks"]})
    for r in rows:
        if r["status"] == "implemented":
            r["status"] = "covered"
    return rows


def summarize(rows: list[dict]) -> dict:
    counts = {
        k: sum(1 for r in rows if r["status"] == k) for k in ("covered", "planned", "not_feasible", "missing")
    }
    total = len(rows)
    feasible = total - counts["not_feasible"]
    return {
        "total": total,
        **counts,
        "covered_percent": round(100 * counts["covered"] / total, 1) if total else 0.0,
        "feasible_covered_percent": round(100 * counts["covered"] / feasible, 1) if feasible else 0.0,
    }


def coverage_report(cat: Path, only: str | None = None) -> dict:
    mapper = Mapper.from_catalog(cat)
    upstreams = load_upstreams(cat)
    inventories = []
    for src in upstreams:
        if only and only not in (src["id"], tool_key(src)):
            continue
        inv = load_inventory(cat, src["id"])
        if inv is None:
            continue
        rows = classify(src, inv["techniques"], mapper)
        inventories.append(
            {
                "source_id": src["id"],
                "name": src["name"],
                "tool": tool_key(src),
                "revision": inv.get("revision"),
                "fetched": inv.get("fetched"),
                "match": match_mode(src),
                **summarize(rows),
                "techniques": rows,
            }
        )
    if only and not inventories:
        known = sorted({s["id"] for s in upstreams} | {tool_key(s) for s in upstreams})
        raise UpstreamError(f"no inventory for {only!r}; known: {', '.join(known)}")
    return {
        "generated": dt.date.today().isoformat(),
        "checks": len(mapper.checks),
        "implemented_checks": sum(
            1 for c in mapper.checks if c.get("status", "implemented") == "implemented"
        ),
        "inventories": inventories,
    }


def render_coverage_text(rep: dict) -> str:
    lines = [
        f"Perdedor coverage of upstream techniques ({rep['implemented_checks']} implemented of "
        f"{rep['checks']} catalogued checks)",
        "",
        f"{'source':<22} {'rev':<14} {'total':>5} {'covered':>7} {'planned':>7} {'n/f':>4} {'missing':>7} "
        f"{'covered%':>8} {'feasible%':>9}",
    ]
    for inv in rep["inventories"]:
        lines.append(
            f"{inv['source_id']:<22} {str(inv['revision'])[:14]:<14} {inv['total']:>5} {inv['covered']:>7} "
            f"{inv['planned']:>7} {inv['not_feasible']:>4} {inv['missing']:>7} "
            f"{inv['covered_percent']:>7.1f}% {inv['feasible_covered_percent']:>8.1f}%"
        )
    return "\n".join(lines)


def render_coverage_markdown(rep: dict) -> str:
    out = [
        "# Coverage of upstream techniques",
        "",
        f"Generated {rep['generated']} from the inventories in `catalog/inventory/` and the "
        f"`equivalents` of {rep['implemented_checks']} implemented checks ({rep['checks']} catalogued). "
        "A technique is covered when an implemented check lists it; not feasible techniques are "
        "documented as such; everything else is missing. *Feasible* excludes the not feasible ones.",
        "",
        "| Source | Revision | Techniques | Covered | Planned | Not feasible | Missing | Covered | Of feasible |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for inv in rep["inventories"]:
        out.append(
            f"| {inv['name']} (`{inv['source_id']}`) | {inv['revision']} | {inv['total']} | {inv['covered']} | "
            f"{inv['planned']} | {inv['not_feasible']} | {inv['missing']} | {inv['covered_percent']:.1f}% | "
            f"{inv['feasible_covered_percent']:.1f}% |"
        )
    for inv in rep["inventories"]:
        missing = [t["name"] for t in inv["techniques"] if t["status"] == "missing"]
        if missing:
            out += [
                "",
                f"## {inv['name']}: missing ({len(missing)})",
                "",
                ", ".join(f"`{n}`" for n in missing),
            ]
    return "\n".join(out)


# ------------------------------------------------------------------------------------------ revisions


def _short_date(stamp: str | None) -> str | None:
    return stamp[:10] if stamp else None


def latest_revision(src: Mapping, gh: GitHub, today: str) -> dict:
    """The newest upstream revision of a source: {version, commit, date, url}."""
    kind = src["kind"]
    repo = src.get("repo", "")
    if kind == "web-page":
        resp = gh.http.get(src["url"], etag=(gh.cache.get(src["url"]) or {}).get("etag"))
        entry = gh.cache.get(src["url"]) or {}
        if resp.status == 304 and "digest" in entry:
            digest = entry["digest"]
        else:
            digest = hashlib.sha256(resp.body).hexdigest()
            if resp.headers.get("etag"):
                gh.cache[src["url"]] = {"etag": resp.headers["etag"], "digest": digest}
        return {"version": f"sha256:{digest[:16]}", "commit": None, "date": today, "url": src["url"]}
    if kind in ("github-release", "attack-stix"):
        rel = gh.latest_release(repo)
        if rel:
            tag = rel["tag_name"]
            commit = gh.resolve(repo, tag)
            return {
                "version": tag,
                "commit": commit["sha"],
                "date": _short_date(rel.get("published_at")),
                "url": rel.get("html_url") or f"https://github.com/{repo}/releases/tag/{tag}",
            }
        kind = "github-tag"  # the project publishes tags but no releases
    if kind == "github-tag":
        names = gh.tag_names(repo, src.get("tag_prefix"))
        if src.get("tag_regex"):
            names = [n for n in names if re.fullmatch(src["tag_regex"], n)]
        if not names:
            raise UpstreamError(f"{repo}: no tag matches")
        tag = max(names, key=version_key)
        commit = gh.resolve(repo, tag)
        return {
            "version": tag,
            "commit": commit["sha"],
            "date": _short_date(commit["commit"]["committer"]["date"]),
            "url": f"https://github.com/{repo}/releases/tag/{tag}",
        }
    # github-commits: the newest commit that touched any tracked path
    paths = [p for p in src.get("paths", []) if p][:COMMIT_PATH_LIMIT] or [None]
    best = None
    for path in paths:
        c = gh.commit(repo, src.get("branch"), path)
        if c and (best is None or c["commit"]["committer"]["date"] > best["commit"]["committer"]["date"]):
            best = c
    if best is None:
        raise UpstreamError(f"{repo}: no commits found")
    return {
        "version": best["sha"][:12],
        "commit": best["sha"],
        "date": _short_date(best["commit"]["committer"]["date"]),
        "url": best.get("html_url") or f"https://github.com/{repo}/commit/{best['sha']}",
    }


def is_update(src: Mapping, latest: Mapping) -> bool:
    pinned = src.get("pinned") or {}
    if src["kind"] == "github-commits":
        return latest.get("commit") != pinned.get("commit")
    return latest.get("version") != pinned.get("version")


def source_ref(src: Mapping, rev: Mapping) -> str:
    """The git ref to read files at: the tag for release and tag sources, otherwise the commit."""
    if src["kind"] in ("github-release", "github-tag", "attack-stix") and rev.get("version"):
        return rev["version"]
    return rev.get("commit") or rev["version"]


def build_inventory(src: Mapping, rev: Mapping, gh: GitHub, today: str) -> dict:
    """Run the source's parser on its files at ``rev`` and return the inventory document."""
    parser = src.get("parser", "none")
    items: list[dict] = []
    if parser in parsers.STIX_PARSERS:
        ref = source_ref(src, rev)

        def objects():
            # One bundle at a time: a connection opened early would idle (and be dropped) while an earlier
            # bundle of tens of megabytes is still being parsed.
            for path in src["paths"]:
                stream = gh.http.stream(gh.raw_url(src["repo"], ref, path))
                try:
                    yield from parsers.iter_json_array(stream)
                finally:
                    stream.close()

        items = parsers.STIX_PARSERS[parser](objects(), src)
    elif parser in parsers.TEXT_PARSERS and parser != "none":
        ref = source_ref(src, rev)
        listing: list[str] | None = None
        files: dict[str, str] = {}
        suffixes = tuple(src.get("suffixes", []))
        for path in src["paths"]:
            if path.endswith("/"):
                listing = listing if listing is not None else gh.tree(src["repo"], ref)
                found = [p for p in listing if p.startswith(path) and (not suffixes or p.endswith(suffixes))]
                if parser in parsers.LISTING_PARSERS:
                    files.update({p: "" for p in found})
                else:
                    for p in found:
                        files[p] = gh.raw(src["repo"], ref, p)
            else:
                files[path] = gh.raw(src["repo"], ref, path)
        items = parsers.TEXT_PARSERS[parser](files, src)
    items.sort(key=lambda i: i["name"])
    return {
        "source_id": src["id"],
        "revision": rev["version"],
        "commit": rev.get("commit"),
        "fetched": today,
        "techniques": items,
    }


def diff_inventory(old: dict | None, new: dict, src: Mapping, mapper: Mapper) -> dict:
    """New and removed techniques against the committed inventory, and which new ones no check maps."""
    old_names = {t["name"] for t in (old or {}).get("techniques", [])}
    new_by_name = {t["name"]: t for t in new["techniques"]}
    added = [new_by_name[n] for n in new_by_name if n not in old_names] if old else []
    removed = sorted(old_names - set(new_by_name)) if old else []
    rows = {r["name"]: r for r in classify(src, added, mapper)}
    return {
        "baseline": bool(old),
        "technique_count": len(new["techniques"]),
        "new_techniques": [
            {
                "name": t["name"],
                "detail": t.get("detail", ""),
                "unmapped": rows[t["name"]]["status"] == "missing",
            }
            for t in added
        ],
        "removed_techniques": removed,
    }


# ------------------------------------------------------------------------------------------- check run


def check_sources(
    upstreams: list[dict],
    cat: Path,
    gh: GitHub,
    state: dict,
    today: str,
    mapper: Mapper | None,
) -> dict:
    results = []
    unmapped_total = []
    for src in upstreams:
        entry: dict[str, Any] = {
            "id": src["id"],
            "name": src["name"],
            "kind": src["kind"],
            "pinned": src.get("pinned"),
            "url": src.get("url"),
        }
        try:
            latest = latest_revision(src, gh, today)
            entry["latest"] = latest
            changed = is_update(src, latest)
            entry["status"] = "update" if changed else "current"
            seen = state["seen"].get(src["id"])
            entry["new_since_last_check"] = bool(
                changed and (not seen or seen.get("version") != latest["version"])
            )
            state["seen"][src["id"]] = {
                "version": latest["version"],
                "commit": latest.get("commit"),
                "at": today,
            }
            if changed:
                entry["change"] = {"from": (src.get("pinned") or {}).get("version"), "to": latest["version"]}
                if src.get("parser", "none") != "none" and mapper is not None:
                    try:
                        new_inv = build_inventory(src, latest, gh, today)
                        entry.update(diff_inventory(load_inventory(cat, src["id"]), new_inv, src, mapper))
                        for t in entry["new_techniques"]:
                            if t["unmapped"]:
                                unmapped_total.append({"source_id": src["id"], **t})
                    except (UpstreamError, OSError, ValueError, KeyError) as exc:
                        entry["inspect_error"] = str(exc)
        except (UpstreamError, OSError, ValueError, KeyError) as exc:
            entry["status"] = "error"
            entry["error"] = str(exc)
            if isinstance(exc, RateLimited):
                results.append(entry)
                entry["error"] += " -- remaining sources were not checked"
                for rest in upstreams[len(results) :]:
                    results.append(
                        {
                            "id": rest["id"],
                            "name": rest["name"],
                            "kind": rest["kind"],
                            "status": "skipped",
                            "pinned": rest.get("pinned"),
                            "url": rest.get("url"),
                        }
                    )
                break
        results.append(entry)
    counts = {
        k: sum(1 for r in results if r["status"] == k) for k in ("current", "update", "error", "skipped")
    }
    return {
        "checked": today,
        "offline": False,
        "summary": {"sources": len(results), **counts, "unmapped_new_techniques": len(unmapped_total)},
        "sources": results,
        "unmapped_upstream_techniques": unmapped_total,
    }


def offline_report(upstreams: list[dict], cat: Path, today: str) -> dict:
    problems = validate_upstreams(upstreams, cat)
    rep = coverage_report(cat)
    sources = []
    for s in upstreams:
        inv = load_inventory(cat, s["id"])
        sources.append(
            {
                "id": s["id"],
                "name": s["name"],
                "kind": s["kind"],
                "status": "offline",
                "pinned": s.get("pinned"),
                "url": s.get("url"),
                "inventory_techniques": len(inv["techniques"]) if inv else None,
            }
        )
    return {
        "checked": today,
        "offline": True,
        "summary": {"sources": len(sources), "problems": len(problems)},
        "problems": problems,
        "sources": sources,
        "coverage": [
            {
                k: i[k]
                for k in (
                    "source_id",
                    "total",
                    "covered",
                    "planned",
                    "not_feasible",
                    "missing",
                    "covered_percent",
                )
            }
            for i in rep["inventories"]
        ],
    }


def render_check_text(res: dict) -> str:
    s = res["summary"]
    if res.get("offline"):
        lines = [f"Offline check of {s['sources']} tracked sources ({s['problems']} problems)"]
        lines += [f"  problem: {p}" for p in res.get("problems", [])]
        for src in res["sources"]:
            pin = src.get("pinned") or {}
            inv = src.get("inventory_techniques")
            lines.append(
                f"  {src['id']:<22} pinned {str(pin.get('version', '?')):<22} {pin.get('date', '?')}  "
                f"{'' if inv is None else f'{inv} techniques'}"
            )
        lines.append("")
        lines.append("Coverage of the committed inventories:")
        for c in res.get("coverage", []):
            lines.append(
                f"  {c['source_id']:<22} {c['covered']:>3}/{c['total']:<4} covered "
                f"({c['covered_percent']:.1f}%), {c['not_feasible']} not feasible, {c['missing']} missing"
            )
        return "\n".join(lines)
    lines = [
        f"Upstream check {res['checked']}: {s['sources']} sources, {s['update']} with updates, "
        f"{s['error']} errors, {s['unmapped_new_techniques']} new unmapped techniques"
    ]
    for src in res["sources"]:
        st = src["status"]
        pin = (src.get("pinned") or {}).get("version", "?")
        if st == "update":
            lines.append(
                f"  UPDATE  {src['id']:<22} {pin} -> {src['latest']['version']}   {src['latest'].get('url', '')}"
            )
            new = src.get("new_techniques", [])
            if new:
                names = ", ".join(t["name"] + ("" if t["unmapped"] else " (mapped)") for t in new[:20])
                lines.append(
                    f"          {len(new)} new upstream techniques: {names}{' ...' if len(new) > 20 else ''}"
                )
            if src.get("removed_techniques"):
                lines.append(f"          removed upstream: {', '.join(src['removed_techniques'][:20])}")
            if src.get("inspect_error"):
                lines.append(f"          could not list techniques: {src['inspect_error']}")
        elif st == "error":
            lines.append(f"  ERROR   {src['id']:<22} {src['error']}")
        elif st == "skipped":
            lines.append(f"  skipped {src['id']}")
        else:
            lines.append(f"  ok      {src['id']:<22} {pin}")
    return "\n".join(lines)


def exit_code(res: dict) -> int:
    s = res["summary"]
    if s.get("problems"):
        return EXIT_ERROR
    if s.get("update"):
        return EXIT_UPDATES
    if s.get("error") or s.get("skipped"):
        return EXIT_ERROR
    return EXIT_OK


# ----------------------------------------------------------------------------------------- commands


def _token(args: argparse.Namespace) -> str | None:
    if not args.token_env:
        return None
    value = os.environ.get(args.token_env)
    if not value:
        print(
            f"warning: ${args.token_env} is empty or unset; querying GitHub unauthenticated", file=sys.stderr
        )
        return None
    return value


def _make_http(args: argparse.Namespace) -> Http:
    return Http(token=_token(args))


def _today() -> str:
    return dt.date.today().isoformat()


def cmd_check(args: argparse.Namespace, http: Http | None = None) -> int:
    try:
        cat = catalog_dir(args.catalog)
        upstreams = load_upstreams(cat)
        state_path = Path(args.state) if args.state else default_state_path()
        if args.offline:
            res = offline_report(upstreams, cat, _today())
            print(json.dumps(res, indent=2) if args.json else render_check_text(res))
            return exit_code(res)
        state = load_state(state_path)
        gh = GitHub(http or _make_http(args), state["cache"])
        res = check_sources(upstreams, cat, gh, state, _today(), Mapper.from_catalog(cat))
        state["last_result"] = res
        state["updated"] = _today()
        try:
            write_json(state_path, state)
        except OSError as exc:
            print(f"warning: cannot write state file {state_path}: {exc}", file=sys.stderr)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(res, indent=2) if args.json else render_check_text(res))
    return exit_code(res)


def cmd_status(args: argparse.Namespace) -> int:
    path = Path(args.state) if args.state else default_state_path()
    try:
        state = load_state(path)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    res = state.get("last_result")
    if not res:
        print(f"no check recorded in {path}; run `perdedor upstream check`", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(res, indent=2) if args.json else render_check_text(res))
    return exit_code(res)


def cmd_pin(args: argparse.Namespace, http: Http | None = None) -> int:
    try:
        cat = catalog_dir(args.catalog)
        state = load_state(Path(args.state) if args.state else default_state_path())
        res = state.get("last_result")
        if not res or res.get("offline"):
            raise UpstreamError(
                "no online check recorded in the state file; run `perdedor upstream check` first"
            )
        moved = {s["id"]: s for s in res["sources"] if s["status"] == "update"}
        wanted = list(moved) if args.all else args.ids
        if not wanted:
            raise UpstreamError("name the sources to pin, or --all; pending: " + (", ".join(moved) or "none"))
        for sid in wanted:
            if sid not in moved:
                raise UpstreamError(f"{sid}: no pending update in the last check")
        doc = load_json(cat / "upstreams.json")
        gh = GitHub(http or _make_http(args), state["cache"]) if args.inventory else None
        today = _today()
        for src in doc["upstreams"]:
            if src["id"] not in wanted:
                continue
            latest = moved[src["id"]]["latest"]
            src["pinned"] = {
                "version": latest["version"],
                "commit": latest.get("commit"),
                "date": today,
                **({"released": latest["date"]} if latest.get("date") and latest["date"] != today else {}),
            }
            if gh is not None and src.get("parser", "none") != "none":
                write_json(cat / "inventory" / f"{src['id']}.json", build_inventory(src, latest, gh, today))
            print(f"pinned {src['id']} to {latest['version']}")
        write_json(cat / "upstreams.json", doc)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_refresh(args: argparse.Namespace, http: Http | None = None) -> int:
    """Rebuild inventories from the upstream files at the pinned (default) or the latest revision."""
    try:
        cat = catalog_dir(args.catalog)
        upstreams = load_upstreams(cat)
        known = {s["id"] for s in upstreams}
        for sid in args.ids:
            if sid not in known:
                raise UpstreamError(f"unknown source {sid!r}")
        gh = GitHub(http or _make_http(args))
        today = _today()
        failures = 0
        for src in upstreams:
            if (args.ids and src["id"] not in args.ids) or src.get("parser", "none") == "none":
                continue
            try:
                if args.at == "latest":
                    rev = latest_revision(src, gh, today)
                else:
                    pin = src["pinned"]
                    rev = {"version": pin["version"], "commit": pin.get("commit"), "date": pin.get("date")}
                inv = build_inventory(src, rev, gh, today)
                write_json(cat / "inventory" / f"{src['id']}.json", inv)
                print(f"{src['id']}: {len(inv['techniques'])} techniques at {inv['revision']}")
            except (UpstreamError, OSError, ValueError, KeyError) as exc:
                failures += 1
                print(f"{src['id']}: {exc}", file=sys.stderr)
        return EXIT_ERROR if failures else EXIT_OK
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def cmd_coverage(args: argparse.Namespace) -> int:
    try:
        rep = coverage_report(catalog_dir(args.catalog), args.tool)
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(json.dumps(rep, indent=2))
    elif args.markdown:
        print(render_coverage_markdown(rep))
    else:
        print(render_coverage_text(rep))
    return EXIT_OK


# ------------------------------------------------------------------------------------------- parsers


def register(subparsers: Any) -> None:
    up = subparsers.add_parser(
        "upstream",
        help="watch the projects Perdedor mirrors for new releases and techniques",
        description="Exit codes of `check`: 0 nothing new, 10 updates available, 1 error.",
    )
    sub = up.add_subparsers(dest="upstream_command", required=True)

    def common(p: argparse.ArgumentParser, with_net: bool = True) -> None:
        p.add_argument("--catalog", help="catalog directory (default: the repository catalog)")
        if with_net:
            p.add_argument(
                "--token-env",
                metavar="VAR",
                help="name of an environment variable holding a GitHub token (raises the rate limit; never printed)",
            )

    chk = sub.add_parser("check", help="query upstream and report updates and unmapped techniques")
    chk.add_argument("--state", help="state file (default: $XDG_STATE_HOME/perdedor/upstream-state.json)")
    chk.add_argument("--json", action="store_true", help="print the result as JSON")
    chk.add_argument(
        "--offline", action="store_true", help="no network: validate pins and inventories, show coverage"
    )
    common(chk)
    chk.set_defaults(func=cmd_check)

    st = sub.add_parser("status", help="print the result of the last check")
    st.add_argument("--state", help="state file")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    pin = sub.add_parser("pin", help="record reviewed updates as the new pinned revisions")
    pin.add_argument("ids", nargs="*", metavar="ID", help="source ids")
    pin.add_argument("--all", action="store_true", help="pin every pending update")
    pin.add_argument(
        "--inventory", action="store_true", help="also rewrite the inventories of the pinned sources"
    )
    pin.add_argument("--state", help="state file")
    common(pin)
    pin.set_defaults(func=cmd_pin)

    ref = sub.add_parser("refresh", help="rebuild catalog/inventory/*.json from the upstream sources")
    ref.add_argument("ids", nargs="*", metavar="ID", help="source ids (default: all with a parser)")
    ref.add_argument(
        "--at", choices=("pinned", "latest"), default="pinned", help="revision to read (default: pinned)"
    )
    common(ref)
    ref.set_defaults(func=cmd_refresh)

    cov = subparsers.add_parser(
        "coverage", help="which upstream techniques the check catalog covers, plans, rules out or misses"
    )
    cov.add_argument("--tool", help="one source id or tool key (vmaware, al-khaser, pafish, ...)")
    fmt = cov.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--markdown", action="store_true")
    cov.add_argument("--catalog", help="catalog directory (default: the repository catalog)")
    cov.set_defaults(func=cmd_coverage)
