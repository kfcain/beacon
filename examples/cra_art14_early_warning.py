"""CRA Article 14 early-warning evidence packer. Load with BEACON_PLUGIN_PATH.

KEV listing and severity are signals only. They do not set product exploitation
or a notification duty. Those fields stay undetermined unless a human or a
separate policy input sets them explicitly.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Literal, NoReturn

from beacon.config import env, format_iso8601
from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec

PLUGIN_NAME = "cra.art14.early_warning"
SCHEMA_VERSION = "1.0"
ARTICLE_ID = "CRA-Art-14"
DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cra.art14.early_warning.json"
LIVE_TIMEOUT_SEC = 20
BLOCKED_KEV_HOSTS = frozenset({"localhost", "localhost.localdomain", "metadata.google.internal"})
INVALID_KEV_URL = "invalid-kev-url"
# Alternate numeric hosts (127.1, 2130706433, 0177.0.0.1, 0x7f.0.0.1) must not
# fall through to the system resolver after ipaddress.ip_address() fails.
_NUMERIC_HOST_SEGMENT = re.compile(r"^(?:0x[0-9a-f]+|\d+)$")
_DNS_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$")

ExploitationStatus = Literal["undetermined", "confirmed", "not_applicable"]
NotificationStatus = Literal["not_evaluated", "notified", "not_required", "deferred"]
CollectMode = Literal["live", "fixture", "live_failed"]

EXPLOITATION_STATUSES: tuple[ExploitationStatus, ...] = (
    "undetermined",
    "confirmed",
    "not_applicable",
)
NOTIFICATION_STATUSES: tuple[NotificationStatus, ...] = (
    "not_evaluated",
    "notified",
    "not_required",
    "deferred",
)

DISCLAIMER = (
    "CISA KEV listing and vulnerability severity are signals only. They do not "
    "establish that a product with digital elements is being exploited, that the "
    "manufacturer has become aware of active exploitation in that product, or that "
    "a CRA Article 14 notification is required. Exploitation and notification "
    "status stay undetermined until an explicit human or separate policy input "
    "sets them. This packer records evidence. It is not legal advice and it does "
    "not file ENISA or CSIRT notifications."
)


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value}")


def _now() -> str:
    return format_iso8601(dt.datetime.now(dt.timezone.utc))


def _norm(value: str) -> str:
    return " ".join(value.casefold().split())


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the next URL still passes KEV URL rules."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        _https_url(redirected.full_url)
        return redirected


def _http_get_json(url: str, timeout: int = LIVE_TIMEOUT_SEC) -> dict[str, Any]:
    safe_url = _https_url(url)
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    request = urllib.request.Request(
        safe_url,
        headers={"User-Agent": "beacon-cra-art14-early-warning/0.1", "Accept": "application/json"},
    )
    with opener.open(request, timeout=timeout) as response:
        raw = response.read()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("KEV response is not a JSON object")
    _require_kev_catalog(data)
    return data


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
    if mapped is not None:
        ip = mapped
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _looks_like_numeric_host_alias(hostname: str) -> bool:
    if ":" in hostname:
        return True
    parts = hostname.split(".")
    return bool(parts) and all(_NUMERIC_HOST_SEGMENT.fullmatch(part) for part in parts)


def _is_dns_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    if not any("a" <= char <= "z" for char in hostname):
        return False
    return all(_DNS_LABEL.fullmatch(label) for label in hostname.split("."))


def _host_blocked(host: str | None) -> bool:
    if not host:
        return True
    hostname = host.strip("[]").split("%", 1)[0].rstrip(".").casefold()
    if not hostname or hostname in BLOCKED_KEV_HOSTS or hostname.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return _ip_blocked(ip)
    if _looks_like_numeric_host_alias(hostname):
        return True
    return not _is_dns_hostname(hostname)


def _meta_present(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _count_matches_rows(count: object, row_len: int) -> bool:
    if isinstance(count, bool) or not isinstance(count, int):
        return False
    return count == row_len


def _require_kev_catalog(data: dict[str, Any]) -> dict[str, Any]:
    """Reject JSON objects that are not a KEV catalog envelope."""
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise ValueError("KEV catalog must include a vulnerabilities list")
    has_version = _meta_present(data.get("catalogVersion")) or _meta_present(data.get("catalog_version"))
    has_date = _meta_present(data.get("dateReleased")) or _meta_present(data.get("date_released"))
    has_count = _count_matches_rows(data.get("count"), len(vulns))
    if not (has_version or has_date or has_count):
        raise ValueError("KEV catalog is missing catalogVersion, dateReleased, or matching count")
    return data


def _https_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("KEV URL must be https without embedded credentials")
    if parsed.port not in (None, 443):
        raise ValueError("KEV URL must use HTTPS port 443")
    if _host_blocked(parsed.hostname):
        raise ValueError("KEV URL host is not allowed")
    return url.strip()


def _safe_source_url(url: str) -> str:
    try:
        return _https_url(url)
    except (ValueError, TypeError, AttributeError):
        return INVALID_KEV_URL


def _path_uri(path: Path) -> str:
    return path.expanduser().resolve().as_uri()


def _fixture_path(ctx: CollectContext) -> Path:
    extra = str(ctx.extra.get("fixture_path") or "").strip()
    if extra:
        return Path(extra).expanduser().resolve()
    configured = (env("CRA_FIXTURE_PATH") or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return DEFAULT_FIXTURE


def _kev_url(ctx: CollectContext) -> str:
    extra = str(ctx.extra.get("kev_url") or "").strip()
    if extra:
        return _https_url(extra)
    configured = (env("CRA_KEV_URL") or "").strip()
    if configured:
        return _https_url(configured)
    return DEFAULT_KEV_URL


def _load_fixture(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fixture is not a JSON object")
    return data


def _product_scope(ctx: CollectContext, fixture: dict[str, Any] | None) -> dict[str, Any]:
    extra_scope = ctx.extra.get("product_scope")
    if isinstance(extra_scope, dict) and extra_scope:
        return dict(extra_scope)
    if fixture:
        scope = fixture.get("product_scope")
        if isinstance(scope, dict):
            return dict(scope)
    return {}


def _parse_status(value: object, allowed: tuple[str, ...], field: str) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().casefold()
    if not raw:
        return None
    if raw not in allowed:
        raise ValueError(f"invalid {field}: {value!r}")
    return raw


def _explicit_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _resolve_statuses(
    ctx: CollectContext,
    *,
    fixture: dict[str, Any] | None,
    mode: CollectMode,
) -> tuple[ExploitationStatus, NotificationStatus]:
    extra = ctx.extra
    exploitation = _parse_status(extra.get("exploitation_status"), EXPLOITATION_STATUSES, "exploitation_status")
    notification = _parse_status(extra.get("notification_status"), NOTIFICATION_STATUSES, "notification_status")
    confirmed = _explicit_bool(extra.get("confirmed_exploitation"))
    if mode == "fixture" and fixture is not None:
        if exploitation is None:
            exploitation = _parse_status(
                fixture.get("exploitation_status"), EXPLOITATION_STATUSES, "exploitation_status"
            )
        if notification is None:
            notification = _parse_status(
                fixture.get("notification_status"), NOTIFICATION_STATUSES, "notification_status"
            )
        if confirmed is None:
            confirmed = _explicit_bool(fixture.get("confirmed_exploitation"))
    elif mode == "live":
        pass
    elif mode == "live_failed":
        pass
    else:
        _never(mode)
    if confirmed is True:
        exploitation = "confirmed"
    if exploitation is None:
        exploitation = "undetermined"
    if notification is None:
        notification = "not_evaluated"
    if exploitation not in EXPLOITATION_STATUSES:
        _never(exploitation)
    if notification not in NOTIFICATION_STATUSES:
        _never(notification)
    return exploitation, notification


def _row_cve(row: dict[str, Any]) -> str:
    return str(row.get("cveID") or row.get("cve_id") or "").strip().upper()


def _scope_identities(scope: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    vendor = str(scope.get("vendor") or "")
    product = str(scope.get("product_name") or scope.get("product") or "")
    if vendor or product:
        pairs.append((vendor, product))
    for component in _as_list(scope.get("components")):
        item = _as_dict(component)
        pairs.append((str(item.get("vendor") or ""), str(item.get("name") or item.get("product") or "")))
    return pairs


def _row_matches_scope(row: dict[str, Any], scope: dict[str, Any]) -> bool:
    cve = _row_cve(row)
    watch = {str(item).strip().upper() for item in _as_list(scope.get("watch_cves")) if str(item).strip()}
    if cve and cve in watch:
        return True
    vendor = str(row.get("vendorProject") or row.get("vendor") or "")
    product = str(row.get("product") or "")
    nv_row, np_row = _norm(vendor), _norm(product)
    if not np_row:
        return False
    for want_vendor, want_product in _scope_identities(scope):
        nv_want, np_want = _norm(want_vendor), _norm(want_product)
        if np_want and np_want == np_row:
            if not nv_want or nv_want == nv_row:
                return True
    return False


def _kev_rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in _as_list(catalog.get("vulnerabilities")):
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _signal_from_row(row: dict[str, Any]) -> dict[str, Any]:
    cvss = _as_dict(row.get("cvss"))
    severity = cvss.get("severity") or row.get("severity")
    return {
        "source": "kev",
        "cve_id": _row_cve(row),
        "vendor_project": row.get("vendorProject") or row.get("vendor"),
        "product": row.get("product"),
        "date_added": row.get("dateAdded") or row.get("date_added"),
        "severity": severity,
        "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
        "signal_present": True,
        "does_not_assert_exploitation": True,
    }


def _match_signals(catalog: dict[str, Any], scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matched_rows: list[dict[str, Any]] = []
    matched_signals: list[dict[str, Any]] = []
    if not scope:
        return [], []
    for row in _kev_rows(catalog):
        if _row_matches_scope(row, scope):
            matched_rows.append(row)
            matched_signals.append(_signal_from_row(row))
    return matched_rows, matched_signals


def _observation_kev(
    catalog: dict[str, Any],
    matched_rows: list[dict[str, Any]],
    *,
    source_url: str,
    fetched: bool,
) -> dict[str, Any]:
    return {
        "source": "kev",
        "source_url": source_url,
        "fetched": fetched,
        "catalog_version": catalog.get("catalogVersion") or catalog.get("catalog_version"),
        "date_released": catalog.get("dateReleased") or catalog.get("date_released"),
        "catalog_count": catalog.get("count"),
        "row_count": len(_kev_rows(catalog)),
        "matched_row_count": len(matched_rows),
        "vulnerabilities": matched_rows,
    }


def _findings(
    *,
    exploitation_status: ExploitationStatus,
    notification_status: NotificationStatus,
    matched_count: int,
    signal_present: bool,
) -> list[dict[str, Any]]:
    return [
        {
            "article": ARTICLE_ID,
            "check": "early_warning_signal_pack",
            "status": "signals_recorded",
            "severity": "info",
            "exploitation_status": exploitation_status,
            "notification_status": notification_status,
            "matched_signal_count": matched_count,
            "signal_present": signal_present,
            "kev_is_not_exploitation": True,
            "does_not_assert_notification_duty": True,
            "detail": DISCLAIMER,
        }
    ]


def _payload(
    *,
    mode: CollectMode,
    observed_at: str,
    product_scope: dict[str, Any],
    catalog: dict[str, Any] | None,
    matched_rows: list[dict[str, Any]],
    matched_signals: list[dict[str, Any]],
    exploitation_status: ExploitationStatus,
    notification_status: NotificationStatus,
    source_url: str,
    fixture_reason: str | None,
    error: str | None,
) -> dict[str, Any]:
    observations: dict[str, Any]
    if catalog is None:
        observations = {
            "kev": {
                "source": "kev",
                "source_url": source_url,
                "fetched": False,
                "vulnerabilities": [],
                "error": error,
            }
        }
    else:
        observations = {
            "kev": _observation_kev(catalog, matched_rows, source_url=source_url, fetched=mode == "live")
        }
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "article": ARTICLE_ID,
        "source": PLUGIN_NAME,
        "mode": mode,
        "ok": mode != "live_failed" and error is None,
        "observed_at": observed_at,
        "signal_sources": ["kev"],
        "signal_present": bool(matched_signals),
        "matched_signals": matched_signals,
        "product_scope": product_scope,
        "exploitation_status": exploitation_status,
        "notification_status": notification_status,
        "kev_is_not_exploitation": True,
        "does_not_assert_notification_duty": True,
        "disclaimer": DISCLAIMER,
        "observations": observations,
        "findings": [],
    }
    if mode != "live_failed" and error is None:
        body["findings"] = _findings(
            exploitation_status=exploitation_status,
            notification_status=notification_status,
            matched_count=len(matched_signals),
            signal_present=bool(matched_signals),
        )
    if fixture_reason:
        body["fixture_reason"] = fixture_reason
    if error:
        body["error"] = error
        body["ok"] = False
    return body


def _targets_for(ctx: CollectContext, spec: FetcherSpec) -> tuple[str, ...]:
    if ctx.target:
        return (ctx.target.upper(),)
    return spec.scf_targets


def _use_fixture(ctx: CollectContext) -> bool:
    force_fixture = bool(ctx.extra.get("force_fixture"))
    if ctx.live is True:
        return False
    return force_fixture or ctx.live is False or ctx.live is None


class CraArt14EarlyWarningPlugin:
    spec = FetcherSpec(
        name=PLUGIN_NAME,
        version="0.1.0",
        description=(
            "CRA Article 14 early-warning packer. Records KEV as a signal. "
            "Does not assert product exploitation or a notification duty."
        ),
        category="compliance",
        scf_targets=("GOV-01",),
        tools=(),
    )

    def collect(self, ctx: CollectContext) -> CollectResult:
        if _use_fixture(ctx):
            return self._fixture_result(ctx)
        return self._live_result(ctx)

    def _fixture_result(self, ctx: CollectContext) -> CollectResult:
        path = _fixture_path(ctx)
        try:
            fixture = _load_fixture(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            payload = _payload(
                mode="fixture",
                observed_at=_now(),
                product_scope={},
                catalog=None,
                matched_rows=[],
                matched_signals=[],
                exploitation_status="undetermined",
                notification_status="not_evaluated",
                source_url=_path_uri(path),
                fixture_reason="fixture_unreadable",
                error=str(exc),
            )
            return CollectResult(
                ok=False,
                mode="fixture",
                payload=payload,
                error=str(exc),
                scf_targets=_targets_for(ctx, self.spec),
            )
        catalog = _as_dict(fixture.get("kev"))
        product_scope = _product_scope(ctx, fixture)
        try:
            exploitation_status, notification_status = _resolve_statuses(
                ctx, fixture=fixture, mode="fixture"
            )
        except ValueError as exc:
            payload = _payload(
                mode="fixture",
                observed_at=_now(),
                product_scope=product_scope,
                catalog=catalog,
                matched_rows=[],
                matched_signals=[],
                exploitation_status="undetermined",
                notification_status="not_evaluated",
                source_url=_path_uri(path),
                fixture_reason="invalid_status",
                error=str(exc),
            )
            return CollectResult(
                ok=False,
                mode="fixture",
                payload=payload,
                error=str(exc),
                scf_targets=_targets_for(ctx, self.spec),
            )
        matched_rows, matched_signals = _match_signals(catalog, product_scope)
        reason = "forced_fixture" if ctx.live is False or ctx.extra.get("force_fixture") else "default_offline"
        payload = _payload(
            mode="fixture",
            observed_at=_now(),
            product_scope=product_scope,
            catalog=catalog,
            matched_rows=matched_rows,
            matched_signals=matched_signals,
            exploitation_status=exploitation_status,
            notification_status=notification_status,
            source_url=_path_uri(path),
            fixture_reason=reason,
            error=None,
        )
        return CollectResult(
            ok=True,
            mode="fixture",
            payload=payload,
            scf_targets=_targets_for(ctx, self.spec),
        )

    def _live_failed(self, ctx: CollectContext, error: str, source_url: str) -> CollectResult:
        product_scope = _product_scope(ctx, None)
        if not product_scope:
            try:
                product_scope = _product_scope(ctx, _load_fixture(_fixture_path(ctx)))
            except (OSError, ValueError, json.JSONDecodeError):
                product_scope = {}
        try:
            exploitation_status, notification_status = _resolve_statuses(
                ctx, fixture=None, mode="live_failed"
            )
        except ValueError:
            exploitation_status, notification_status = "undetermined", "not_evaluated"
        payload = _payload(
            mode="live_failed",
            observed_at=_now(),
            product_scope=product_scope,
            catalog=None,
            matched_rows=[],
            matched_signals=[],
            exploitation_status=exploitation_status,
            notification_status=notification_status,
            source_url=source_url,
            fixture_reason=None,
            error=error,
        )
        payload["mode"] = "live_failed"
        payload["ok"] = False
        return CollectResult(
            ok=False,
            mode="live_failed",
            payload=payload,
            error=error,
            scf_targets=_targets_for(ctx, self.spec),
        )

    def _live_result(self, ctx: CollectContext) -> CollectResult:
        raw_url = str(ctx.extra.get("kev_url") or env("CRA_KEV_URL") or DEFAULT_KEV_URL)
        try:
            url = _kev_url(ctx)
        except ValueError as exc:
            return self._live_failed(ctx, str(exc), _safe_source_url(raw_url))
        try:
            catalog = _http_get_json(url)
            _require_kev_catalog(catalog)
        except Exception as exc:
            return self._live_failed(ctx, str(exc), _safe_source_url(url))
        product_scope = _product_scope(ctx, None)
        if not product_scope:
            try:
                product_scope = _product_scope(ctx, _load_fixture(_fixture_path(ctx)))
            except (OSError, ValueError, json.JSONDecodeError):
                product_scope = {}
        try:
            exploitation_status, notification_status = _resolve_statuses(
                ctx, fixture=None, mode="live"
            )
        except ValueError as exc:
            return self._live_failed(ctx, str(exc), url)
        matched_rows, matched_signals = _match_signals(catalog, product_scope)
        payload = _payload(
            mode="live",
            observed_at=_now(),
            product_scope=product_scope,
            catalog=catalog,
            matched_rows=matched_rows,
            matched_signals=matched_signals,
            exploitation_status=exploitation_status,
            notification_status=notification_status,
            source_url=url,
            fixture_reason=None,
            error=None,
        )
        return CollectResult(
            ok=True,
            mode="live",
            payload=payload,
            scf_targets=_targets_for(ctx, self.spec),
        )


PLUGIN = CraArt14EarlyWarningPlugin()
