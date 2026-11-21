#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Core verification statuses, execution receipts, secret/prompt-injection guards, and URL integrity."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Sequence
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit


VALID_STATUSES = ('PASS', 'FAIL', 'INCONCLUSIVE', 'BLOCKED', 'NOT_RUN')

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._\-~+/=]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b(bearer\s+)[A-Za-z0-9._\-~+/=]{8,}'), r'\1[REDACTED]'),
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b'), '[REDACTED_GH_TOKEN]'),
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{20,}\b'), '[REDACTED_API_KEY]'),
    (re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'), '[REDACTED_JWT]'),
    (re.compile(r'(?i)\b((?:cf_clearance|sessionid|connect\.sid|auth_token|access_token|refresh_token|cookie|set-cookie)\s*[:=]\s*)([^\s;"\']+)', re.M), r'\1[REDACTED]'),
    (re.compile(r'(?i)(adb\s+pair\s+\S+\s+)(\d{4,8})'), r'\1[REDACTED_PAIRING_CODE]'),
    (re.compile(r'(?i)(pairing\s*code\s*[:=]\s*)(\d{4,8})'), r'\1[REDACTED_PAIRING_CODE]'),
)

_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('override_instructions', re.compile(r'(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|system|user)\s+(instructions?|rules?|constraints?|scope)\b')),
    ('shell_execution_directive', re.compile(r'(?i)(execute|run)\s*:\s*(touch|rm|curl|wget|bash|sh|python|nc|chmod)\b')),
    ('curl_pipe_shell', re.compile(r'(?i)\b(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b')),
    ('secret_exfiltration', re.compile(r'(?i)\b(read|dump|send|exfiltrate|expose|reveal|print)\b[^\n.]{0,60}\b(credentials?|secrets?|tokens?|env|environment\s+variables?|api[_\s]?keys?|\.ssh)\b')),
    ('scope_expansion', re.compile(r'(?i)\b(overwrite\s+other\s+skills|modify\s+authentication\s+configuration|install\s+an\s+unauthorized\s+dependency)\b')),
)

_TRACKING_PARAM_PREFIXES = ('utm_', 'fbclid', 'gclid', 'mc_cid', 'mc_eid', '_ga', '_gl')
_SAFE_URL_SCHEMES = {'http', 'https'}


@dataclass
class CheckReceipt:
    """Deterministic receipt proving a single verification step."""

    check_id: str
    status: str
    oracle: str
    command: str = ''
    evidence_sha256: str = ''
    timestamp: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    counterexample_tested: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f'invalid status: {self.status!r}')


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode('utf-8'))


def make_receipt(
    check_id: str,
    status: str,
    oracle: str,
    *,
    command: str = '',
    evidence: bytes | str | dict[str, Any] | None = None,
    counterexample_tested: bool = False,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a verifiable execution receipt with SHA-256 evidence digest."""
    if status not in VALID_STATUSES:
        raise ValueError(f'invalid status: {status!r}')
    if isinstance(evidence, bytes):
        ev_hash = sha256_bytes(evidence)
    elif isinstance(evidence, str):
        ev_hash = sha256_text(evidence)
    elif evidence is not None:
        ev_hash = sha256_text(json.dumps(evidence, sort_keys=True, ensure_ascii=False))
    else:
        ev_hash = ''
    receipt = CheckReceipt(
        check_id=check_id,
        status=status,
        oracle=oracle,
        command=command,
        evidence_sha256=ev_hash,
        counterexample_tested=counterexample_tested,
        details=details or {},
    )
    return asdict(receipt)


def verify_receipt(receipt: dict[str, Any]) -> bool:
    """Validate receipt structure; PASS receipts require a non-empty oracle and timestamp."""
    if not isinstance(receipt, dict):
        return False
    status = receipt.get('status')
    if status not in VALID_STATUSES:
        return False
    if not isinstance(receipt.get('check_id'), str) or not receipt['check_id'].strip():
        return False
    if not isinstance(receipt.get('oracle'), str) or not receipt['oracle'].strip():
        return False
    ts = receipt.get('timestamp')
    if not isinstance(ts, str) or not ts:
        return False
    try:
        dt.datetime.fromisoformat(ts)
    except ValueError:
        return False
    if status == 'PASS' and not (receipt.get('evidence_sha256') or receipt.get('details')):
        return False
    return True


def aggregate_status(receipts: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate check receipts honestly without inflating unrun or inconclusive checks."""
    counts = {s: 0 for s in VALID_STATUSES}
    for r in receipts:
        s = r.get('status', 'INCONCLUSIVE') if isinstance(r, dict) else 'FAIL'
        if s not in counts:
            s = 'FAIL'
        counts[s] += 1

    total = len(receipts)
    executed = counts['PASS'] + counts['FAIL']
    if counts['FAIL'] > 0:
        overall = 'FAIL'
    elif total == 0 or counts['PASS'] == 0:
        if counts['BLOCKED'] > 0:
            overall = 'BLOCKED'
        elif counts['INCONCLUSIVE'] > 0:
            overall = 'INCONCLUSIVE'
        else:
            overall = 'NOT_RUN'
    elif counts['BLOCKED'] > 0 or counts['INCONCLUSIVE'] > 0 or counts['NOT_RUN'] > 0:
        overall = 'INCONCLUSIVE'
    else:
        overall = 'PASS'

    # Confidence reflects only verified PASS receipts against all expected checks; unrun never raises score.
    confidence = round(counts['PASS'] / total, 3) if total else 0.0
    return {
        'overall_status': overall,
        'counts': counts,
        'total_checks': total,
        'executed_checks': executed,
        'confidence_score': confidence,
    }


def detect_unsupported_claims(report: dict[str, Any]) -> list[dict[str, str]]:
    """Audit a report dictionary and flag claims lacking executed PASS receipts or real artifacts."""
    findings: list[dict[str, str]] = []
    receipts = report.get('receipts') or []
    by_id = {r.get('check_id'): r for r in receipts if isinstance(r, dict) and r.get('check_id')}

    for claim in report.get('claims', []):
        if not isinstance(claim, dict):
            continue
        text = str(claim.get('statement', ''))
        req_id = claim.get('check_id')
        receipt = by_id.get(req_id) if req_id else None
        if not receipt:
            findings.append({'claim': text, 'reason': f'missing receipt for check_id={req_id!r}'})
        elif not verify_receipt(receipt):
            findings.append({'claim': text, 'reason': f'invalid receipt structure for check_id={req_id!r}'})
        elif receipt['status'] != 'PASS':
            findings.append({'claim': text, 'reason': f"cannot claim success when check status is {receipt['status']}"})

    if report.get('overall_status') == 'PASS':
        if not receipts:
            findings.append({'claim': 'overall_status=PASS', 'reason': 'no verification receipts present'})
        elif any(r.get('status') != 'PASS' for r in receipts if isinstance(r, dict)):
            findings.append({'claim': 'overall_status=PASS', 'reason': 'non-PASS receipts exist'})

    for artifact in report.get('artifacts', []):
        if isinstance(artifact, dict) and artifact.get('claimed_present'):
            path_str = artifact.get('path', '')
            if not path_str or not Path(path_str).is_file():
                findings.append({'claim': f'artifact:{path_str}', 'reason': 'claimed artifact path does not exist on disk'})
            elif artifact.get('sha256'):
                actual = sha256_bytes(Path(path_str).read_bytes())
                if actual != artifact['sha256']:
                    findings.append({'claim': f'artifact:{path_str}', 'reason': 'artifact sha256 mismatch'})

    return findings


def sanitize_text(text: str, *, redact_home: bool = False) -> str:
    """Redact tokens, cookies, API keys, JWTs, and ADB pairing codes from logs/reports."""
    out = text
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    if redact_home:
        home = str(Path.home())
        if home and home != '/':
            out = out.replace(home, '$HOME')
    return out


_HARDCODED_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    re.compile(r'\bAIza[0-9A-Za-z\-_]{20,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'(?i)\b(?:api_?key|auth_?token|access_?token|secret_?key|cf_clearance|password)\s*[:=]\s*["\'][A-Za-z0-9._\-~+/=]{12,}["\']'),
)


def scan_hardcoded_literals(text: str) -> list[dict[str, str]]:
    """Detect potential hardcoded secret literals in source code without flagging variable types/names."""
    hits: list[dict[str, str]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        for pat in _HARDCODED_SECRET_PATTERNS:
            if pat.search(line):
                hits.append({
                    'line': str(idx),
                    'kind': 'secret_pattern',
                    'snippet': sanitize_text(line.strip())[:160],
                })
                break
    return hits


scan_secrets = scan_hardcoded_literals


def scan_prompt_injection(text: str, source_label: str = 'remote-data') -> dict[str, Any]:
    """Scan untrusted text for prompt-injection directives; treat content strictly as data."""
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for kind, pat in _PROMPT_INJECTION_PATTERNS:
            if pat.search(line):
                findings.append({
                    'line': line_no,
                    'kind': kind,
                    'excerpt': sanitize_text(line.strip())[:160],
                })
    return {
        'source': source_label,
        'trusted': False,
        'detected': bool(findings),
        'count': len(findings),
        'findings': findings[:50],
    }


def is_private_or_reserved_host(host: str) -> bool:
    """Return True if host is localhost, a private/loopback/link-local IP, or cloud metadata endpoint."""
    h = host.strip().lower().rstrip('.')
    if not h or h in {'localhost', 'localhost.localdomain', 'metadata.google.internal'}:
        return True
    if h.endswith('.local') or h.endswith('.internal'):
        return True
    try:
        ip = ipaddress.ip_address(h.strip('[]'))
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def is_safe_public_url(url: str, *, allow_private_fixture: bool = False) -> tuple[bool, str]:
    """Validate URL scheme and guard against SSRF to local/private/metadata addresses."""
    try:
        parsed = urlsplit(url.strip())
    except ValueError as exc:
        return False, f'invalid URL syntax: {exc}'
    scheme = parsed.scheme.lower()
    if scheme not in _SAFE_URL_SCHEMES:
        return False, f'disallowed URL scheme: {scheme or "<empty>"}'
    if not parsed.hostname:
        return False, 'missing hostname'
    if parsed.username or parsed.password:
        return False, 'embedded credentials in URL are disallowed'
    if not allow_private_fixture and is_private_or_reserved_host(parsed.hostname):
        return False, f'private or reserved host blocked: {parsed.hostname}'
    return True, 'ok'


def strip_tracking_params(query: str) -> str:
    """Remove tracking parameters while preserving chapter/page/id/signature parameters."""
    if not query:
        return ''
    kept: list[tuple[str, str]] = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        kl = k.lower()
        if any(kl == p or kl.startswith(p) for p in _TRACKING_PARAM_PREFIXES if p.endswith('_')) or kl in _TRACKING_PARAM_PREFIXES:
            continue
        kept.append((k, v))
    return urlencode(kept, doseq=True)


def normalize_url(url: str, *, strip_tracking: bool = True, drop_fragment: bool = True) -> str:
    """Normalize scheme/host casing, UTF-8 percent-encoding, and optional tracking params."""
    raw = url.strip()
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f'URL must be absolute: {url!r}')
    scheme = parsed.scheme.lower()
    if scheme not in _SAFE_URL_SCHEMES:
        raise ValueError(f'unsupported URL scheme: {scheme}')
    host = (parsed.hostname or '').lower()
    port = f':{parsed.port}' if parsed.port and not ((scheme == 'http' and parsed.port == 80) or (scheme == 'https' and parsed.port == 443)) else ''
    path = quote(unquote(parsed.path or '/'), safe="/:@-._~!$&'()*+,;=")
    # Collapse duplicate slashes inside path without touching scheme://
    path = re.sub(r'/+', '/', path)
    query = strip_tracking_params(parsed.query) if strip_tracking else parsed.query
    fragment = '' if drop_fragment else parsed.fragment
    return urlunsplit((scheme, f'{host}{port}', path, query, fragment))


def resolve_relative_url(base_url: str, href: str, *, allowed_hosts: Iterable[str] | None = None) -> str:
    """Safely resolve relative or absolute href against base_url without naive string concatenation."""
    if not href or not href.strip():
        raise ValueError('empty href')
    candidate = href.strip()
    lower = candidate.lower()
    if lower.startswith(('javascript:', 'data:', 'vbscript:', 'file:')):
        raise ValueError(f'dangerous href scheme: {candidate!r}')
    resolved = urljoin(normalize_url(base_url, strip_tracking=False), candidate)
    normalized = normalize_url(resolved, strip_tracking=False)
    if allowed_hosts is not None:
        allowed = {h.lower().lstrip('.') for h in allowed_hosts}
        host = (urlsplit(normalized).hostname or '').lower()
        if not any(host == a or host.endswith('.' + a) for a in allowed):
            raise ValueError(f'resolved host {host!r} outside allowed hosts {sorted(allowed)}')
    return normalized


def validate_redirect_chain(
    hops: Sequence[str],
    *,
    allowed_hosts: Iterable[str] | None = None,
    max_hops: int = 8,
    allow_private_fixture: bool = False,
) -> dict[str, Any]:
    """Verify redirect chain for loops, excessive hops, HTTPS downgrades, and unauthorized host escapes."""
    if not hops:
        return {'status': 'FAIL', 'reason': 'empty redirect chain'}
    if len(hops) > max_hops:
        return {'status': 'FAIL', 'reason': f'redirect chain exceeds max_hops={max_hops}'}

    seen: set[str] = set()
    allowed = {h.lower().lstrip('.') for h in allowed_hosts} if allowed_hosts is not None else None
    downgraded = False
    prev_scheme = ''

    for hop in hops:
        ok, msg = is_safe_public_url(hop, allow_private_fixture=allow_private_fixture)
        if not ok:
            return {'status': 'FAIL', 'reason': msg, 'hop': hop}
        norm = normalize_url(hop, strip_tracking=False)
        if norm in seen:
            return {'status': 'FAIL', 'reason': f'redirect loop detected at {norm}', 'hop': norm}
        seen.add(norm)
        parsed = urlsplit(norm)
        if prev_scheme == 'https' and parsed.scheme == 'http':
            downgraded = True
        prev_scheme = parsed.scheme

    final_url = normalize_url(hops[-1], strip_tracking=False)
    final_host = (urlsplit(final_url).hostname or '').lower()
    if allowed is not None and not any(final_host == a or final_host.endswith('.' + a) for a in allowed):
        return {
            'status': 'FAIL',
            'reason': f'final redirect host {final_host!r} is outside allowed domain scope',
            'final_url': final_url,
            'final_host': final_host,
        }
    if downgraded:
        return {'status': 'FAIL', 'reason': 'HTTPS downgraded to HTTP in redirect chain', 'final_url': final_url}
    return {'status': 'PASS', 'final_url': final_url, 'final_host': final_host, 'hop_count': len(hops)}


def atomic_write_text(path: Path, content: str, encoding: str = 'utf-8') -> None:
    """Write text atomically to avoid corrupting files on interruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        tmp.write_text(content, encoding=encoding)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


_BIDI_CONTROLS = frozenset('\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')


def scan_bidi_controls(text: str) -> list[dict[str, Any]]:
    """Detect hidden Unicode bidirectional control chars (Trojan Source defense)."""
    hits: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        found = [f'U+{ord(ch):04X}' for ch in line if ch in _BIDI_CONTROLS]
        if found:
            hits.append({'line': line_no, 'codepoints': sorted(set(found))})
    return hits


def verify_report_claims(report_path: Path | str, root: Path | str) -> dict[str, Any]:
    """Independently verify file paths and SHA-256 checksums referenced inside a Markdown audit report."""
    rp = Path(report_path)
    base = Path(root).resolve()
    if not rp.is_file():
        return {'status': 'FAIL', 'error': f'report missing: {rp}'}
    content = rp.read_text(encoding='utf-8')
    missing_paths: list[str] = []
    checked_paths: list[str] = []
    hash_mismatches: list[dict[str, str]] = []
    checked_hashes = 0

    # Verify backticked repo-relative file paths that look like project files
    for m in re.finditer(r'`((?:scripts|tests|docs|references|evidencias)/[A-Za-z0-9_.\-/]+)`', content):
        rel = m.group(1)
        if '*' in rel or '<' in rel or rel.endswith('/'):
            continue
        target = base / rel
        checked_paths.append(rel)
        if not target.exists():
            missing_paths.append(rel)

    # Verify SHA-256 pairs `sha256: <64-hex>` or `<64-hex>  <path>` if sha256sums.txt exists
    sha_file = base / 'evidencias/sha256sums.txt'
    if sha_file.is_file():
        for ln in sha_file.read_text(encoding='utf-8').splitlines():
            parts = ln.strip().split(None, 1)
            if len(parts) == 2 and re.fullmatch(r'[0-9a-f]{64}', parts[0]):
                expected_sha, rel_p = parts[0], parts[1].strip()
                fp = base / rel_p
                if not fp.is_file():
                    missing_paths.append(rel_p)
                else:
                    checked_hashes += 1
                    actual_sha = sha256_bytes(fp.read_bytes())
                    if actual_sha != expected_sha:
                        hash_mismatches.append({'file': rel_p, 'expected': expected_sha, 'actual': actual_sha})

    ok = not missing_paths and not hash_mismatches
    return {
        'status': 'PASS' if ok else 'FAIL',
        'report': str(rp),
        'checked_paths_count': len(set(checked_paths)),
        'missing_paths': sorted(set(missing_paths)),
        'checked_hashes_count': checked_hashes,
        'hash_mismatches': hash_mismatches,
    }


def _plain_language_summary(result: dict[str, Any], lang: str) -> tuple[str, str]:
    """Translate structured technical results into concise, jargon-free beginner guidance."""
    st = str(result.get('status') or 'INCONCLUSIVE').upper()
    is_en = lang == 'en'
    reason = str(result.get('user_summary') or result.get('reason') or result.get('error') or '').strip()
    eco = result.get('ecosystem') or result.get('inferred_ecosystem')

    if st == 'PASS':
        msg = (
            f'Everything worked cleanly{" for " + str(eco) if eco else ""}.'
            if is_en
            else f'Tudo funcionou corretamente{" para " + str(eco) if eco else ""}.'
        )
        nxt = (
            'Test a search, open chapters, and check images or video inside the app. Let me know if anything looks off.'
            if is_en
            else 'Agora voce ja pode testar a busca, os capitulos e o carregamento de imagens ou video no app. Se algo falhar, me avise.'
        )
        return msg, nxt

    if st == 'BLOCKED':
        lower_r = reason.lower()
        if 'adb' in lower_r or 'device' in lower_r:
            msg = (
                'This automatic check did not find a phone or emulator connected, which is optional.'
                if is_en
                else 'Nao encontrei celular ou emulador conectado agora — essa etapa e totalmente opcional.'
            )
            nxt = (
                'Everything else ran locally without a phone. Connect an Android device via USB debugging only if you want an extra live screen check.'
                if is_en
                else 'O restante ja foi validado automaticamente. So conecte o celular com depuracao USB se voce quiser testar a tela ao vivo.'
            )
            return msg, nxt
        if 'sandbox' in lower_r or 'bwrap' in lower_r or 'unsafe' in lower_r or 'untrusted' in lower_r or 'gradlew' in lower_r:
            msg = (
                'Blocked automatic build for your safety because isolated execution could not be guaranteed.'
                if is_en
                else 'Bloqueei a compilacao automatica por seguranca porque nao foi possivel isolar a execucao com seguranca.'
            )
            nxt = (
                'Review the project safety checks and verify bubblewrap isolation is active before compiling.'
                if is_en
                else 'Verifique os requisitos de isolamento e a integridade do projeto antes de tentar compilar.'
            )
            return msg, nxt
        msg = (
            'Automatic execution paused because a required local check is unavailable or blocked.'
            if is_en
            else 'A execucao automatica parou porque falta um recurso local obrigatorio ou ha um bloqueio de seguranca.'
        )
        nxt = (
            'Share what step stopped or confirm whether you want a guided next action.'
            if is_en
            else 'Me diga em que ponto parou ou se quer que eu mostre a alternativa mais simples.'
        )
        return msg, nxt

    if st == 'FAIL':
        msg = (
            'Found an issue that stopped this step from succeeding.'
            if is_en
            else 'Encontrei um problema que impediu esta etapa de funcionar corretamente.'
        )
        nxt = (
            'I will try an alternative strategy or adjust the failing check before retrying.'
            if is_en
            else 'Vou tentar uma abordagem alternativa para resolver sem repetir o mesmo erro.'
        )
        return msg, nxt

    msg = (
        'Completed partial checks, though some details could not be confirmed automatically.'
        if is_en
        else 'Conclui as verificacoes possiveis, mas alguns detalhes nao puderam ser confirmados automaticamente.'
    )
    nxt = (
        'Tell me what happens when you open the source (for example: empty list, loading error, or missing covers).'
        if is_en
        else 'Me conte o que aparece para voce (ex.: lista vazia, erro ao abrir ou capas sem carregar).'
    )
    return msg, nxt


def build_agent_continuation(
    *,
    phase: str,
    task_complete: bool,
    status: str,
    completed_gates: dict[str, str],
    next_agent_action: str,
) -> dict[str, Any]:
    """Build deterministic continuation directive preventing agents from stopping at templates or diagnostics."""
    must_continue = (not task_complete) and (status.upper() != 'BLOCKED')
    return {
        'task_complete': task_complete,
        'must_continue_automatically': must_continue,
        'current_phase': phase,
        'completed_gates': completed_gates,
        'next_agent_action': next_agent_action,
        'do_not_ask_user': [
            'Do not ask permission to inspect site, consult docs/issues, scaffold, implement selectors, run tests, fix errors, or compile in sandbox.',
        ],
    }


def _persist_internal_diagnostics(result: dict[str, Any], diagnostics_dir: Path | str | None = None) -> Path:
    """Persist full technical details in an internal file without exposing dumps in beginner answers."""
    cand = diagnostics_dir or result.get('output_dir') or result.get('diagnostics_dir')
    target_dir = Path(cand) if cand else None
    if target_dir and target_dir.is_dir():
        diag_path = target_dir / '.nox-diagnostics' / 'latest-report.json'
    else:
        diag_path = Path(tempfile.gettempdir()) / f'nox-diagnostics-{os.getpid()}.json'
    atomic_write_text(diag_path, json.dumps(result, indent=2, ensure_ascii=False, default=str) + '\n')
    return diag_path


def format_adaptive_response(
    result: dict[str, Any],
    *,
    technical: bool = False,
    lang: str = 'pt-BR',
    diagnostics_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Return dual-layer output: clean beginner payload backed by an internal diagnostics file, or full technical JSON."""
    user_message, next_step = _plain_language_summary(result, lang)
    custom_msg = result.get('user_message')
    if isinstance(custom_msg, str) and custom_msg.strip():
        user_message = custom_msg.strip()
    custom_next = result.get('next_step')
    if isinstance(custom_next, str) and custom_next.strip():
        next_step = custom_next.strip()

    status = str(result.get('status') or 'INCONCLUSIVE').upper()
    diag_path = _persist_internal_diagnostics(result, diagnostics_dir=diagnostics_dir)

    if technical:
        return {
            **result,
            'mode': 'technical',
            'status': status,
            'user_message': user_message,
            'next_step': next_step,
            'diagnostics_file': str(diag_path),
        }

    apk_ready = bool(result.get('apk_ready'))
    return {
        'mode': 'beginner',
        'status': status,
        'action': result.get('action'),
        'ecosystem': result.get('ecosystem') or result.get('inferred_ecosystem'),
        'user_message': user_message,
        'next_step': next_step,
        'code_implemented': bool(result.get('code_implemented')),
        'code_modified': bool(result.get('code_modified')),
        'tests_verified': bool(result.get('tests_verified')),
        'persisted_files': list(result.get('persisted_files') or []),
        'artifact_path': result.get('artifact_path'),
        'apk_ready': apk_ready,
        'apk_path': result.get('apk_path') if apk_ready else None,
        'apk_options': result.get('apk_options') if apk_ready else None,
        'limitations': result.get('user_limitations'),
        'diagnostics_file': str(diag_path),
        'agent_continuation': result.get('agent_continuation'),
    }


def detect_investigation_loop(
    attempts: Sequence[dict[str, Any]],
    *,
    max_repeats: int = 2,
) -> dict[str, Any]:
    """Detect repeated debugging cycles without progress and propose escalating alternatives."""
    if max_repeats < 2:
        max_repeats = 2

    def _tally(field_name: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in attempts:
            raw = str(item.get(field_name) or '').strip()
            if not raw:
                continue
            norm = re.sub(r'\s+', ' ', raw).lower()[:160]
            counts[norm] = counts.get(norm, 0) + 1
        return {k: v for k, v in counts.items() if v >= max_repeats}

    repeated_errors = _tally('error')
    repeated_selectors = _tally('selector')
    repeated_patches = _tally('patch_hash')
    repeated_hypotheses = _tally('hypothesis')

    loop_detected = bool(
        repeated_errors or repeated_selectors or repeated_patches or repeated_hypotheses
    )
    stagnation_count = max(
        [0, *repeated_errors.values(), *repeated_selectors.values(), *repeated_patches.values(), *repeated_hypotheses.values()]
    )

    combined_errors = ' '.join(repeated_errors.keys())
    if any(tok in combined_errors for tok in ('403', '429', 'cloudflare', 'captcha', 'tls', 'timeout')):
        stagnation_category = 'network_or_protection'
    elif repeated_selectors or any(tok in combined_errors for tok in ('selector', 'empty', 'null', 'missing')):
        stagnation_category = 'selector_drift'
    elif any(tok in combined_errors for tok in ('401', 'token', 'auth', 'cookie', 'nonce')):
        stagnation_category = 'auth_or_token'
    elif any(tok in combined_errors for tok in ('nosuchmethod', 'abstract', 'signature', 'gradle', 'compile')):
        stagnation_category = 'runtime_mismatch'
    else:
        stagnation_category = 'generic_stagnation' if loop_detected else 'none'

    alternatives: list[str] = []
    if loop_detected:
        if stagnation_category == 'network_or_protection':
            alternatives.append('Inspect real HTTP status, redirect chain, and response headers (Cloudflare/rate-limit) instead of tweaking HTML selectors.')
        elif stagnation_category == 'selector_drift':
            alternatives.append('Compare full fetched HTML/JSON or API endpoints via site-inspect rather than guessing another CSS selector.')
        elif stagnation_category == 'auth_or_token':
            alternatives.append('Trace token/cookie origin in site scripts or API requests without disabling TLS checks.')
        elif stagnation_category == 'runtime_mismatch':
            alternatives.append('Inspect merged PR diffs and API contracts matching the exact extension API version before another edit.')
        alternatives.extend([
            'Capture an isolated reproduction fixture demonstrating the exact failure before editing source files again.',
            'Consult merged upstream PR fixes in the same ecosystem and library generation rather than repeating unverified changes.',
            'Offer optional ADB runtime inspection ONLY if offline parsing passes and the defect reproduces solely inside the Android app.',
        ])

    return {
        'status': 'FAIL' if loop_detected else 'PASS',
        'loop_detected': loop_detected,
        'attempts_analyzed': len(attempts),
        'stagnation_count': stagnation_count,
        'stagnation_category': stagnation_category,
        'repeated_errors': repeated_errors,
        'repeated_selectors': repeated_selectors,
        'repeated_patches': repeated_patches,
        'repeated_hypotheses': repeated_hypotheses,
        'recommended_alternatives': alternatives,
    }
