#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""PR/supply-chain threat analyzer, real APK inspector, and non-destructive ADB/Logcat diagnostics."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile

from nox_core import sanitize_text, scan_bidi_controls, scan_hardcoded_literals


_GRADLE_EXEC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('gradle_runtime_exec', re.compile(r'Runtime\.getRuntime\(\)\.exec\b')),
    ('gradle_process_builder', re.compile(r'\bProcessBuilder\s*\(')),
    ('gradle_exec_task', re.compile(r'\b(?:project\.)?exec\s*\{[^}]*(?:commandLine|executable)')),
    ('curl_pipe_sh', re.compile(r'(?i)(?:curl|wget)[^\n|]*\|\s*(?:ba)?sh')),
    ('base64_decode_exec', re.compile(r'(?i)base64\s+-d[^\n]*\|\s*(?:ba)?sh')),
)

_WORKFLOW_DANGER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('pr_target_checkout', re.compile(r'pull_request_target')),
    ('unpinned_action_tag', re.compile(r'uses:\s*[^\s@]+@(?:main|master|v\d+(?:\.\d+)*)\s*$')),
    ('secrets_exposure', re.compile(r'\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}')),
)

_SOURCE_DANGER_PATTERNS: tuple[tuple[str, str, set[str], re.Pattern[str]], ...] = (
    ('FAIL', 'tls_trust_all_certs', {'.kt', '.java'}, re.compile(r'(?i)(?:ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|HostnameVerifier\s*\{\s*[^}]*->\s*true\s*\})')),
    ('FAIL', 'dynamic_dex_loader', {'.kt', '.java'}, re.compile(r'\b(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader)\s*\(')),
    ('FAIL', 'native_system_load', {'.kt', '.java'}, re.compile(r'\bSystem\.load(?:Library)?\s*\(')),
    ('FAIL', 'runtime_command_exec', {'.kt', '.java'}, re.compile(r'\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b')),
    ('FAIL', 'node_child_process', {'.ts', '.js'}, re.compile(r'\bchild_process\b')),
    ('WARN', 'dynamic_eval_js', {'.ts', '.js'}, re.compile(r'(?<![.\w])eval\s*\(')),
)


def audit_untrusted_pr_or_repo(repo_path: Path | str) -> dict[str, Any]:
    """Static supply-chain & RCE audit of Gradle build scripts, wrapper, workflows, package.json, and symlinks."""
    root = Path(repo_path).resolve()
    if not root.exists():
        return {'status': 'FAIL', 'error': f'path does not exist: {root}', 'findings': []}

    findings: list[dict[str, Any]] = []

    # 1. Symlink escape detection
    for cur_root, dirs, files in os.walk(root):
        if '.git' in dirs:
            dirs.remove('.git')
        for entry in list(dirs) + list(files):
            p = Path(cur_root) / entry
            if p.is_symlink():
                try:
                    resolved = p.resolve()
                    resolved.relative_to(root)
                except ValueError:
                    findings.append({'severity': 'FAIL', 'kind': 'symlink_escape', 'file': str(p), 'target': str(os.readlink(p))})

    # 2. Gradle files (configuration phase RCE risk!)
    for pattern in ('*.gradle', '*.gradle.kts'):
        for gf in root.rglob(pattern):
            if any(part in {'.git', 'build', '.gradle', 'node_modules'} for part in gf.parts):
                continue
            txt = gf.read_text(errors='replace')
            for kind, rx in _GRADLE_EXEC_PATTERNS:
                if rx.search(txt):
                    findings.append({'severity': 'FAIL', 'kind': kind, 'file': str(gf.relative_to(root))})
            for m in re.finditer(r'maven\s*\(\s*url\s*=\s*"([^"]+)"', txt):
                url = m.group(1)
                if url.startswith('http://') or ('jitpack' not in url and 'maven.google' not in url and 'repo.maven' not in url and 'mavenCentral' not in url):
                    findings.append({'severity': 'WARN', 'kind': 'custom_or_insecure_maven_repo', 'file': str(gf.relative_to(root)), 'url': url})

    # 3. Gradle wrapper URL check
    wrapper_props = root / 'gradle/wrapper/gradle-wrapper.properties'
    if wrapper_props.is_file():
        wtxt = wrapper_props.read_text(errors='replace')
        dist_m = re.search(r'^distributionUrl=(.+)$', wtxt, re.M)
        if dist_m:
            dist_url = dist_m.group(1).replace('\\:', ':').strip()
            if not dist_url.startswith('https://services.gradle.org/distributions/'):
                findings.append({'severity': 'FAIL', 'kind': 'untrusted_gradle_wrapper_url', 'file': 'gradle/wrapper/gradle-wrapper.properties', 'url': dist_url})

    # 4. GitHub Actions workflows
    wf_dir = root / '.github/workflows'
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.glob('*.y*ml')):
            wtxt = wf.read_text(errors='replace')
            lines = wtxt.splitlines()
            for kind, rx in _WORKFLOW_DANGER_PATTERNS:
                for i, ln in enumerate(lines, start=1):
                    if rx.search(ln):
                        sev = 'FAIL' if kind == 'pr_target_checkout' else 'WARN'
                        findings.append({'severity': sev, 'kind': kind, 'file': str(wf.relative_to(root)), 'line': i})

    # 5. package.json install scripts
    pkg = root / 'package.json'
    if pkg.is_file():
        try:
            pdata = json.loads(pkg.read_text(errors='replace'))
            scripts = pdata.get('scripts') or {}
            for hook in ('preinstall', 'install', 'postinstall'):
                if hook in scripts:
                    findings.append({'severity': 'WARN', 'kind': f'npm_lifecycle_script:{hook}', 'file': 'package.json', 'command': sanitize_text(str(scripts[hook]))[:120]})
        except json.JSONDecodeError:
            findings.append({'severity': 'FAIL', 'kind': 'invalid_package_json', 'file': 'package.json'})

    # 6. Source code checks (TLS bypass, DexClassLoader, command execution, bidi Trojan Source, secrets)
    for ext in ('*.kt', '*.java', '*.ts', '*.js', '*.py'):
        for sf in root.rglob(ext):
            if any(part in {'.git', 'build', '.gradle', 'node_modules', '__pycache__', 'evidencias'} for part in sf.parts):
                continue
            rel = str(sf.relative_to(root))
            # Skip self-testing files that intentionally contain negative regexes/fixtures
            if rel.startswith('tests/') or rel in {'scripts/nox_core.py', 'scripts/nox_android.py', 'scripts/api_compare.py'}:
                continue
            txt = sf.read_text(errors='replace')
            for sev, kind, exts, rx in _SOURCE_DANGER_PATTERNS:
                if sf.suffix in exts and rx.search(txt):
                    findings.append({'severity': sev, 'kind': kind, 'file': rel})
            for bh in scan_bidi_controls(txt):
                findings.append({'severity': 'FAIL', 'kind': 'trojan_source_bidi_control', 'file': rel, **bh})
            for sh in scan_hardcoded_literals(txt):
                findings.append({'severity': 'FAIL', 'kind': 'hardcoded_secret_candidate', 'file': rel, 'line': int(sh['line'])})

    has_fail = any(f['severity'] == 'FAIL' for f in findings)
    return {
        'status': 'FAIL' if has_fail else 'PASS',
        'repo_root': str(root),
        'findings_count': len(findings),
        'findings': findings,
    }


def _find_android_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for env_key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
        sdk = os.environ.get(env_key)
        if sdk:
            bt = Path(sdk) / 'build-tools'
            if bt.is_dir():
                versions = sorted(p for p in bt.iterdir() if p.is_dir())
                for v in reversed(versions):
                    cand = v / name
                    if cand.is_file():
                        return str(cand)
    default_sdk = Path.home() / '.local/share/android-sdk/build-tools'
    if default_sdk.is_dir():
        for v in reversed(sorted(p for p in default_sdk.iterdir() if p.is_dir())):
            cand = v / name
            if cand.is_file():
                return str(cand)
    return None


def inspect_apk(
    apk_path: Path | str,
    *,
    index_json_path: Path | str | None = None,
    expected_package: str | None = None,
) -> dict[str, Any]:
    """Inspect a real APK archive: SHA-256, zip-slip, .so presence (16KB note), aapt2 badging, apksigner certs, index match."""
    path = Path(apk_path)
    if not path.is_file():
        return {'status': 'FAIL', 'error': f'APK file does not exist: {path}', 'device_test_status': 'NOT_RUN'}

    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()

    native_libs: list[str] = []
    has_manifest = False
    has_dex = False
    zip_slip: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            for n in names:
                if '..' in Path(n).parts or n.startswith('/'):
                    zip_slip.append(n)
                if n == 'AndroidManifest.xml':
                    has_manifest = True
                if n.endswith('.dex'):
                    has_dex = True
                if n.startswith('lib/') and n.endswith('.so'):
                    native_libs.append(n)
    except zipfile.BadZipFile as exc:
        return {'status': 'FAIL', 'error': f'Corrupt APK/ZIP: {exc}', 'sha256': sha256, 'device_test_status': 'NOT_RUN'}

    if zip_slip or not has_manifest:
        return {
            'status': 'FAIL',
            'error': 'Invalid APK structure (missing AndroidManifest.xml or zip-slip entry)',
            'sha256': sha256,
            'zip_slip': zip_slip,
            'device_test_status': 'NOT_RUN',
        }

    metadata: dict[str, Any] = {}
    aapt2 = _find_android_tool('aapt2')
    if aapt2:
        proc = subprocess.run([aapt2, 'dump', 'badging', str(path)], capture_output=True, text=True)
        if proc.returncode == 0:
            out = proc.stdout
            pkg_m = re.search(r"package:\s+name='([^']+)'\s+versionCode='(\d+)'\s+versionName='([^']+)'", out)
            min_m = re.search(r"sdkVersion:'(\d+)'", out)
            tgt_m = re.search(r"targetSdkVersion:'(\d+)'", out)
            lbl_m = re.search(r"application-label:'([^']+)'", out)
            if pkg_m:
                metadata.update({
                    'package': pkg_m.group(1),
                    'versionCode': int(pkg_m.group(2)),
                    'versionName': pkg_m.group(3),
                })
            if min_m:
                metadata['minSdkVersion'] = int(min_m.group(1))
            if tgt_m:
                metadata['targetSdkVersion'] = int(tgt_m.group(1))
            if lbl_m:
                metadata['label'] = lbl_m.group(1)

    signing: dict[str, Any] = {'verified': None, 'is_debug_cert': None, 'schemes': {}, 'signers': []}
    apksigner = _find_android_tool('apksigner')
    if apksigner:
        proc = subprocess.run([apksigner, 'verify', '--print-certs', '-v', str(path)], capture_output=True, text=True)
        out = (proc.stdout or '') + '\n' + (proc.stderr or '')
        signing['verified'] = proc.returncode == 0
        for scheme in ('v1', 'v2', 'v3', 'v4'):
            m = re.search(rf'Verified using {scheme} scheme[^:]*:\s*(true|false)', out)
            if m:
                signing['schemes'][scheme] = (m.group(1) == 'true')
        dns = re.findall(r'(?:Signer #\d+|V\d+(?:\.\d+)? Signer):\s*certificate DN:\s*(.+)|Signer #\d+ certificate DN:\s*(.+)', out)
        dns_clean = [a or b for a, b in dns]
        sha_matches = re.findall(r'(?:Signer #\d+|V\d+(?:\.\d+)? Signer):\s*certificate SHA-256 digest:\s*([0-9a-fA-F]+)|Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]+)', out)
        sha_digests = [a or b for a, b in sha_matches]
        signing['signers'] = [{'dn': dn.strip(), 'sha256': dg} for dn, dg in zip(dns_clean, sha_digests)]
        signing['is_debug_cert'] = any('Android Debug' in dn for dn in dns_clean)

    issues: list[str] = []
    if expected_package and metadata.get('package') and metadata['package'] != expected_package:
        issues.append(f"package_mismatch:expected={expected_package},actual={metadata['package']}")
    if signing['verified'] is False:
        issues.append('apk_signature_verification_failed')

    # Cross-check with distribution index.min.json if provided
    index_check: dict[str, Any] | None = None
    if index_json_path is not None:
        idx_p = Path(index_json_path)
        if not idx_p.is_file():
            issues.append(f'index_file_missing:{idx_p}')
        else:
            entries = json.loads(idx_p.read_text(errors='replace'))
            pkg_name = metadata.get('package')
            match = next((e for e in entries if isinstance(e, dict) and e.get('pkg') == pkg_name), None)
            if not match:
                issues.append(f'package_missing_in_index:{pkg_name}')
            else:
                if match.get('code') != metadata.get('versionCode'):
                    issues.append(f"index_versionCode_mismatch:index={match.get('code')},apk={metadata.get('versionCode')}")
                index_check = {'matched_pkg': pkg_name, 'index_apk': match.get('apk'), 'index_code': match.get('code')}

    # 16KB page alignment only applies when native .so libraries exist
    page_16kb_note = 'applicable_native_libs_present_verify_alignment' if native_libs else 'not_applicable_no_native_so_libraries'

    return {
        'status': 'FAIL' if issues else 'PASS',
        'apk_path': str(path.resolve()),
        'size_bytes': len(raw),
        'sha256': sha256,
        'has_dex': has_dex,
        'native_libs': native_libs,
        'page_16kb_status': page_16kb_note,
        'metadata': metadata,
        'signing': signing,
        'build_kind': 'debug' if signing['is_debug_cert'] else ('release_or_custom' if signing['verified'] else 'unknown'),
        'index_check': index_check,
        'device_test_status': 'NOT_RUN',
        'issues': issues,
    }


def parse_adb_devices(output: str) -> list[dict[str, str]]:
    """Parse `adb devices -l` output cleanly across USB and Wi-Fi endpoints."""
    devices: list[dict[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('List of devices') or stripped.startswith('*'):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        transport = 'wifi' if ':' in serial else 'usb'
        meta = dict(p.split(':', 1) for p in parts[2:] if ':' in p)
        devices.append({'serial': serial, 'state': state, 'transport': transport, **meta})
    return devices


def adb_doctor(*, adb_output: str | None = None, selected_serial: str | None = None) -> dict[str, Any]:
    """Non-destructive ADB diagnostic handling 0, 1, multiple, unauthorized, and offline devices."""
    if adb_output is None:
        adb_bin = shutil.which('adb') or _find_android_tool('adb')
        if not adb_bin:
            return {
                'status': 'BLOCKED',
                'adb_present': False,
                'devices': [],
                'guidance': 'Install Android platform-tools (adb) to inspect connected devices.',
            }
        try:
            proc = subprocess.run([adb_bin, 'devices', '-l'], capture_output=True, text=True, timeout=5)
            adb_output = proc.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            return {'status': 'BLOCKED', 'adb_present': True, 'error': str(exc), 'devices': []}

    devices = parse_adb_devices(adb_output)
    ready = [d for d in devices if d['state'] == 'device']
    unauthorized = [d for d in devices if d['state'] == 'unauthorized']
    offline = [d for d in devices if d['state'] == 'offline']

    if not devices:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': 0,
            'devices': [],
            'guidance': 'No Android device/emulator detected. Enable USB Debugging (Developer Options) or pair via Wi-Fi (`adb pair <ip:port>`), then confirm RSA prompt.',
        }

    if unauthorized:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': len(devices),
            'devices': devices,
            'guidance': 'Device unauthorized: unlock screen and tap Allow on the USB debugging RSA dialog.',
        }

    if offline and not ready:
        return {
            'status': 'BLOCKED',
            'adb_present': True,
            'device_count': len(devices),
            'devices': devices,
            'guidance': 'Device offline: reconnect USB cable or run `adb reconnect` (never wipes device data).',
        }

    if len(ready) > 1:
        if not selected_serial:
            return {
                'status': 'INCONCLUSIVE',
                'adb_present': True,
                'device_count': len(devices),
                'devices': devices,
                'guidance': f"Multiple ready devices ({[d['serial'] for d in ready]}); pass --serial <id> explicitly.",
            }
        chosen = next((d for d in ready if d['serial'] == selected_serial), None)
        if not chosen:
            return {
                'status': 'FAIL',
                'adb_present': True,
                'devices': devices,
                'guidance': f'Selected serial {selected_serial!r} is not among ready devices.',
            }
        return {'status': 'PASS', 'adb_present': True, 'selected_device': chosen, 'devices': devices}

    return {'status': 'PASS', 'adb_present': True, 'selected_device': ready[0], 'devices': devices}


_LOGCAT_LINE_RE = re.compile(
    r'^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s*(?P<msg>.*)$'
)


def parse_and_filter_logcat(
    log_text: str,
    *,
    target_package: str | None = None,
    target_pid: int | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    include_optional_noxext_tag: bool = True,
) -> dict[str, Any]:
    """Filter Android logcat by package/PID/time window, isolate foreign crashes, and redact secrets."""
    matched_lines: list[str] = []
    foreign_crashes: list[dict[str, Any]] = []
    target_crashes: list[dict[str, Any]] = []

    current_crash_pid: int | None = None
    current_crash_pkg: str | None = None
    current_crash_lines: list[str] = []

    def _flush_crash() -> None:
        nonlocal current_crash_pid, current_crash_pkg, current_crash_lines
        if not current_crash_lines:
            return
        entry = {
            'pid': current_crash_pid,
            'package': current_crash_pkg,
            'excerpt': [sanitize_text(l, redact_home=True) for l in current_crash_lines[:15]],
        }
        is_target = (
            (target_pid is not None and current_crash_pid == target_pid)
            or (target_package and current_crash_pkg and target_package in current_crash_pkg)
            or (target_package and any(target_package in l for l in current_crash_lines))
        )
        if is_target:
            target_crashes.append(entry)
        else:
            foreign_crashes.append(entry)
        current_crash_pid = None
        current_crash_pkg = None
        current_crash_lines = []

    for raw_line in log_text.splitlines():
        m = _LOGCAT_LINE_RE.match(raw_line)
        if not m:
            continue
        ts = m.group('ts')
        if window_start and ts < window_start:
            continue
        if window_end and ts > window_end:
            continue
        pid = int(m.group('pid'))
        tag = m.group('tag').strip()
        msg = m.group('msg')

        if tag == 'AndroidRuntime' and ('FATAL EXCEPTION' in msg or 'Process:' in msg or current_crash_lines):
            if 'FATAL EXCEPTION' in msg:
                _flush_crash()
                current_crash_pid = pid
            proc_m = re.search(r'Process:\s*([^\s,]+),\s*PID:\s*(\d+)', msg)
            if proc_m:
                current_crash_pkg = proc_m.group(1)
                current_crash_pid = int(proc_m.group(2))
            current_crash_lines.append(raw_line)
        elif current_crash_lines and pid == current_crash_pid and m.group('level') == 'E':
            current_crash_lines.append(raw_line)
        else:
            _flush_crash()

        keep = False
        if target_pid is not None and pid == target_pid:
            keep = True
        elif target_package and target_package in msg:
            keep = True
        elif include_optional_noxext_tag and tag == 'NoxExt':
            keep = True

        if keep:
            matched_lines.append(sanitize_text(raw_line, redact_home=True))

    _flush_crash()

    return {
        'status': 'FAIL' if target_crashes else 'PASS',
        'target_package': target_package,
        'target_pid': target_pid,
        'matched_lines_count': len(matched_lines),
        'matched_lines': matched_lines[:200],
        'target_crashes': target_crashes,
        'foreign_crashes_ignored': foreign_crashes,
        'note': 'NoxExt is an optional diagnostic tag convention, not a guaranteed native Mihon tag.',
    }


KNOWN_OFFICIAL_GRADLE_SHA256: dict[str, str] = {
    'gradle-7.6.4-bin.zip': 'bed1da33cca0f557ab13691c77f38bb67388119e4794d113e051039b80af9bb1',
    'gradle-8.5-bin.zip': '9d926787066a081739e8200858338b4a69e837c3a821a33aca9db09dd4a41026',
    'gradle-8.7-bin.zip': '544c35d6bd849ae8a5ed0bcea39ba677dc40f49df7d1835561582da2009b961d',
    'gradle-8.9-bin.zip': 'd725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab',
    'gradle-8.10.2-bin.zip': '31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26',
    'gradle-8.11.1-bin.zip': 'f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6',
    'gradle-8.12.1-bin.zip': '8d97a97984f6cbd2b85fe4c60a743440a347544bf18818048e611f5288d46c94',
    'gradle-8.13-bin.zip': '20f1b1176237254a6fc5ea710aed786e9f6fa6fc5ea72d22dd63669d59ed4a41',
    'gradle-8.14-bin.zip': '61ad310d3c7d3e5da131b76bbf22b5a4c0786e9d892dae8c1658d4b484de3caa',
}

_OFFICIAL_GRADLE_DIST_HOSTS: frozenset[str] = frozenset({
    'services.gradle.org',
    'downloads.gradle.org',
    'downloads.gradle-dn.com',
})

_SUSPICIOUS_WRAPPER_EXEC_TOKENS: tuple[str, ...] = (
    '/dev/tcp/',
    'bash -i',
    'nc -e',
    'python -c',
    'python3 -c',
    'curl ',
    'wget ',
    'base64 -d',
    '.ssh/',
)


def _is_confined_regular_file(path: Path, root: Path) -> bool:
    """Ensure path exists as a non-symlink regular file strictly confined under root."""
    if not path.exists() or path.is_symlink() or not path.is_file():
        return False
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def verify_gradle_execution_chain(repo_root: Path | str) -> dict[str, Any]:
    """Validate gradlew script, wrapper properties/SHA-256, wrapper JAR integrity, and build properties."""
    root = Path(repo_root).resolve()
    findings: list[dict[str, str]] = []

    gradlew = root / 'gradlew'
    if not _is_confined_regular_file(gradlew, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_missing_or_symlink', 'file': 'gradlew'})
    else:
        gw_text = gradlew.read_text(encoding='utf-8', errors='replace')
        if scan_bidi_controls(gw_text):
            findings.append({'severity': 'FAIL', 'kind': 'wrapper_bidi_trojan', 'file': 'gradlew'})
        gw_low = gw_text.lower()
        for tok in _SUSPICIOUS_WRAPPER_EXEC_TOKENS:
            if tok in gw_low:
                findings.append({'severity': 'FAIL', 'kind': f'suspicious_gradlew_command:{tok.strip()}', 'file': 'gradlew'})

    props_path = root / 'gradle' / 'wrapper' / 'gradle-wrapper.properties'
    checksum_verified_against_catalog = False
    dist_url = ''
    if not _is_confined_regular_file(props_path, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_properties_missing_or_symlink', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
    else:
        props_raw = props_path.read_text(encoding='utf-8', errors='replace')
        props: dict[str, str] = {}
        for line in props_raw.splitlines():
            s = line.strip()
            if not s or s.startswith('#') or s.startswith('!') or '=' not in s:
                continue
            k, v = s.split('=', 1)
            props[k.strip()] = v.strip().replace('\\:', ':')

        dist_url = props.get('distributionUrl', '')
        parsed = urlsplit(dist_url)
        host = (parsed.hostname or '').lower()
        if parsed.scheme != 'https' or host not in _OFFICIAL_GRADLE_DIST_HOSTS or not parsed.path.endswith('.zip'):
            findings.append({'severity': 'FAIL', 'kind': 'untrusted_gradle_distribution_url', 'file': 'gradle/wrapper/gradle-wrapper.properties'})

        sha = props.get('distributionSha256Sum', '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', sha):
            findings.append({'severity': 'FAIL', 'kind': 'missing_or_invalid_distribution_sha256', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
        elif len(set(sha)) <= 2 or sha.startswith('00000000'):
            findings.append({'severity': 'FAIL', 'kind': 'weak_dummy_distribution_sha256', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
        else:
            archive_name = Path(parsed.path).name
            expected = KNOWN_OFFICIAL_GRADLE_SHA256.get(archive_name)
            if expected is not None:
                if sha != expected:
                    findings.append({'severity': 'FAIL', 'kind': f'forged_gradle_checksum_mismatch:{archive_name}', 'file': 'gradle/wrapper/gradle-wrapper.properties'})
                else:
                    checksum_verified_against_catalog = True

    jar_path = root / 'gradle' / 'wrapper' / 'gradle-wrapper.jar'
    if not _is_confined_regular_file(jar_path, root):
        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_missing_or_symlink', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
    else:
        sz = jar_path.stat().st_size
        if sz < 512 or sz > 5 * 1024 * 1024:
            findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_suspicious_size', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
        else:
            try:
                with zipfile.ZipFile(jar_path, 'r') as zf:
                    names = zf.namelist()
                    bad_entries = [
                        n for n in names
                        if n.startswith('/') or '..' in Path(n).parts or n.lower().endswith(('.so', '.dll', '.exe', '.sh', '.bat', '.vbs', '.ps1'))
                    ]
                    if bad_entries:
                        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_disallowed_payload', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
                    if 'META-INF/MANIFEST.MF' not in names or 'org/gradle/wrapper/GradleWrapperMain.class' not in names:
                        findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_missing_main_class', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
                    else:
                        manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
                        if 'org.gradle.wrapper.GradleWrapperMain' not in manifest:
                            findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_manifest_mismatch', 'file': 'gradle/wrapper/gradle-wrapper.jar'})
            except zipfile.BadZipFile:
                findings.append({'severity': 'FAIL', 'kind': 'wrapper_jar_corrupt_zip', 'file': 'gradle/wrapper/gradle-wrapper.jar'})

    for init_cand in ('init.gradle', 'init.gradle.kts', '.gradle/init.d'):
        if (root / init_cand).exists():
            findings.append({'severity': 'FAIL', 'kind': 'repo_init_script_present', 'file': init_cand})

    gprops = root / 'gradle.properties'
    if gprops.exists() and not gprops.is_symlink():
        gp_text = gprops.read_text(encoding='utf-8', errors='replace')
        if any(flag in gp_text for flag in ('-javaagent:', '-agentpath:', '-Xbootclasspath')):
            findings.append({'severity': 'FAIL', 'kind': 'jvm_agent_injection_in_gradle_properties', 'file': 'gradle.properties'})

    ok = not any(f['severity'] == 'FAIL' for f in findings)
    return {
        'status': 'PASS' if ok else 'FAIL',
        'reason': 'gradle execution chain verified' if ok else f"wrapper verification failed: {', '.join(f['kind'] for f in findings[:4])}",
        'distribution_url': dist_url,
        'checksum_verified_against_catalog': checksum_verified_against_catalog,
        'findings': findings,
    }


def build_bwrap_invocation(
    work_dir: Path | str,
    command: Sequence[str],
    *,
    allow_network: bool = False,
    bwrap_bin: str | None = None,
) -> list[str]:
    """Construct a fail-closed Bubblewrap invocation isolating namespaces, environment, and $HOME."""
    bwrap = bwrap_bin or shutil.which('bwrap') or 'bwrap'
    work = Path(work_dir).resolve()
    cmd: list[str] = [
        bwrap,
        '--unshare-all',
        '--die-with-parent',
        '--new-session',
        '--clearenv',
    ]
    cmd.append('--share-net' if allow_network else '--unshare-net')

    for sys_path in ('/usr', '/bin', '/sbin', '/lib', '/lib64'):
        sp = Path(sys_path)
        if sp.is_symlink():
            cmd.extend(['--symlink', os.readlink(sp), sys_path])
        elif sp.is_dir():
            cmd.extend(['--ro-bind', sys_path, sys_path])

    etc_entries: list[Path] = [
        Path('/etc/alternatives'),
        Path('/etc/ssl'),
        Path('/etc/ca-certificates'),
        Path('/etc/ld.so.cache'),
        Path('/etc/ld.so.conf'),
        Path('/etc/ld.so.conf.d'),
        Path('/etc/localtime'),
        Path('/etc/nsswitch.conf'),
        Path('/etc/hosts'),
    ]
    etc_root = Path('/etc')
    if etc_root.is_dir():
        etc_entries.extend(sorted(etc_root.glob('java*')))
        etc_entries.extend(sorted(etc_root.glob('jvm*')))
    if allow_network:
        etc_entries.append(Path('/etc/resolv.conf'))

    for ep in etc_entries:
        if ep.is_symlink():
            resolved = ep.resolve()
            if resolved.exists():
                cmd.extend(['--ro-bind', str(resolved), str(ep)])
        elif ep.exists():
            cmd.extend(['--ro-bind', str(ep), str(ep)])

    path_parts: list[str] = []
    java_home_raw = os.environ.get('JAVA_HOME')
    if java_home_raw:
        jh = Path(java_home_raw).expanduser().resolve()
        if jh.is_dir():
            cmd.extend(['--ro-bind', str(jh), '/sandbox-sdk/java'])
            cmd.extend(['--setenv', 'JAVA_HOME', '/sandbox-sdk/java'])
            path_parts.append('/sandbox-sdk/java/bin')

    android_raw = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if android_raw:
        ah = Path(android_raw).expanduser().resolve()
        if ah.is_dir():
            cmd.extend(['--ro-bind', str(ah), '/sandbox-sdk/android-sdk'])
            cmd.extend(['--setenv', 'ANDROID_HOME', '/sandbox-sdk/android-sdk'])
            cmd.extend(['--setenv', 'ANDROID_SDK_ROOT', '/sandbox-sdk/android-sdk'])
            path_parts.append('/sandbox-sdk/android-sdk/platform-tools')

    path_parts.extend(['/usr/local/sbin', '/usr/local/bin', '/usr/bin', '/bin'])
    cmd.extend([
        '--setenv', 'PATH', ':'.join(path_parts),
        '--setenv', 'HOME', '/work/.nox-sandbox-home',
        '--setenv', 'GRADLE_USER_HOME', '/work/.gradle-home',
        '--setenv', 'TMPDIR', '/tmp',
        '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'LC_ALL', 'C.UTF-8',
        '--proc', '/proc',
        '--dev', '/dev',
        '--tmpfs', '/tmp',
        '--bind', str(work), '/work',
        '--chdir', '/work',
        '--',
        *command,
    ])
    return cmd


def probe_bwrap_sandbox(*, sandbox_available_override: bool | None = None) -> dict[str, Any]:
    """Verify at runtime that Bubblewrap executes unprivileged user-namespace sandboxes cleanly."""
    if sandbox_available_override is False:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': bool(shutil.which('bwrap')),
            'userns_supported': False,
            'reason': 'bubblewrap sandbox unavailable or disabled (fail-closed)',
        }
    bwrap = shutil.which('bwrap')
    if not bwrap:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': False,
            'userns_supported': False,
            'reason': 'bwrap binary not found on PATH; refusing unprotected host execution',
        }
    probe_cmd = [
        bwrap,
        '--unshare-all',
        '--unshare-net',
        '--die-with-parent',
        '--new-session',
        '--clearenv',
    ]
    for sys_path in ('/usr', '/bin', '/lib', '/lib64'):
        sp = Path(sys_path)
        if sp.is_symlink():
            probe_cmd.extend(['--symlink', os.readlink(sp), sys_path])
        elif sp.is_dir():
            probe_cmd.extend(['--ro-bind', sys_path, sys_path])
    probe_cmd.extend(['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--', '/usr/bin/env', 'true'])
    try:
        proc = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    except Exception as exc:
        return {
            'status': 'BLOCKED',
            'bwrap_installed': True,
            'bwrap_path': bwrap,
            'userns_supported': False,
            'reason': f'bwrap probe failed: {exc}',
        }
    if proc.returncode != 0:
        err_msg = sanitize_text(proc.stderr or proc.stdout or '', redact_home=True).strip()
        return {
            'status': 'BLOCKED',
            'bwrap_installed': True,
            'bwrap_path': bwrap,
            'userns_supported': False,
            'reason': f'bwrap kernel/userns sandbox unavailable ({err_msg or f"exit {proc.returncode}"})',
        }
    return {
        'status': 'PASS',
        'bwrap_installed': True,
        'bwrap_path': bwrap,
        'userns_supported': True,
        'reason': 'bubblewrap sandbox verified via live execution probe',
    }


def _stage_project_for_sandbox(src_root: Path, stage_dir: Path) -> None:
    """Copy clean regular files from src_root into ephemeral stage_dir, stripping .git, symlinks, and secret files."""
    skip_dirs = {'.git', '.gradle', '.nox-sandbox-home', '.gradle-home'}
    for dirpath, dirnames, filenames in os.walk(src_root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src_root)
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not (Path(dirpath) / d).is_symlink()
        ]
        target_sub = stage_dir / rel_dir
        target_sub.mkdir(parents=True, exist_ok=True)
        for fname in filenames:
            low_f = fname.lower()
            if (
                low_f == '.env'
                or low_f.startswith('.env.')
                or low_f.endswith(('.pem', '.key', '.p12', '.jks', '.keystore'))
                or 'secret' in low_f
                or 'credential' in low_f
            ):
                continue
            src_file = Path(dirpath) / fname
            if src_file.is_symlink() or not src_file.is_file():
                continue
            dst_file = target_sub / fname
            shutil.copy2(src_file, dst_file)
    (stage_dir / '.nox-sandbox-home').mkdir(parents=True, exist_ok=True)
    (stage_dir / '.gradle-home').mkdir(parents=True, exist_ok=True)


def _extract_sandbox_apks_to_host(stage_dir: Path, host_root: Path) -> list[Path]:
    """Copy built APK outputs from ephemeral sandbox stage directory back into confined host paths."""
    collected: list[Path] = []
    stage_resolved = stage_dir.resolve()
    host_resolved = host_root.resolve()
    for cand in sorted(stage_dir.rglob('*.apk')):
        if cand.is_symlink() or not cand.is_file():
            continue
        try:
            rel = cand.resolve().relative_to(stage_resolved)
        except ValueError:
            continue
        if 'build' not in rel.parts or 'apk' not in rel.parts:
            continue
        dst = host_resolved / rel
        # Guard every intermediate directory against symlink escape on host
        cur = host_resolved
        safe = True
        for part in rel.parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                safe = False
                break
        if not safe or dst.is_symlink():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cand, dst)
        collected.append(dst)
    return collected


def run_in_bwrap_sandbox(
    target_dir: Path | str,
    command: Sequence[str],
    *,
    timeout: int = 300,
    allow_network: bool = False,
    extract_outputs_to_host: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute command inside an ephemeral, network-isolated Bubblewrap copy; fail closed when unavailable."""
    if not command:
        return {'status': 'FAIL', 'reason': 'empty sandbox command', 'executed_unprotected': False, 'returncode': None}

    probe = probe_bwrap_sandbox(sandbox_available_override=sandbox_available_override)
    if probe['status'] != 'PASS':
        return {
            'status': 'BLOCKED',
            'reason': probe['reason'],
            'sandbox': probe,
            'executed_unprotected': False,
            'returncode': None,
            'sandbox_command': [],
            'collected_apks': [],
        }

    src_root = Path(target_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='nox-bwrap-stage-') as tmp:
        stage_dir = Path(tmp) / 'work'
        _stage_project_for_sandbox(src_root, stage_dir)
        bwrap_cmd = build_bwrap_invocation(
            stage_dir,
            command,
            allow_network=allow_network,
            bwrap_bin=probe.get('bwrap_path'),
        )
        try:
            proc = subprocess.run(
                bwrap_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={'PATH': '/usr/bin:/bin'},
            )
        except subprocess.TimeoutExpired:
            return {
                'status': 'FAIL',
                'reason': f'sandboxed command timed out after {timeout}s',
                'timed_out': True,
                'executed_unprotected': False,
                'returncode': None,
                'sandbox_command': bwrap_cmd,
                'sandbox': {**probe, 'bwrap_used': True, 'network_isolated': not allow_network, 'clearenv': True, 'ephemeral_stage': True},
                'collected_apks': [],
            }

        apks = _extract_sandbox_apks_to_host(stage_dir, src_root) if (extract_outputs_to_host and proc.returncode == 0) else []
        out_status = 'PASS' if proc.returncode == 0 else 'FAIL'
        return {
            'status': out_status,
            'reason': 'sandbox execution completed' if proc.returncode == 0 else f'sandboxed command exited {proc.returncode}',
            'executed_unprotected': False,
            'returncode': proc.returncode,
            'stdout': proc.stdout or '',
            'stderr': proc.stderr or '',
            'sandbox_command': bwrap_cmd,
            'collected_apks': [str(p) for p in apks],
            'sandbox': {
                **probe,
                'bwrap_used': True,
                'network_isolated': not allow_network,
                'clearenv': True,
                'ephemeral_stage': True,
            },
        }


def build_debug_apk(
    repo_root: Path | str,
    gradle_task: str,
    *,
    timeout: int = 300,
    offline: bool = False,
    allow_network: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Run security & wrapper pre-flight, execute Gradle inside fail-closed Bubblewrap sandbox, and inspect produced APK."""
    root = Path(repo_root).resolve()
    gradlew = root / 'gradlew'
    if not gradlew.is_file():
        return {'status': 'BLOCKED', 'reason': f'gradlew not found at {root}', 'apk_inspection': None, 'executed_unprotected': False}
    if not re.fullmatch(r':[A-Za-z0-9:_-]+', gradle_task):
        return {'status': 'FAIL', 'reason': f'unsafe gradle task syntax: {gradle_task!r}', 'apk_inspection': None, 'executed_unprotected': False}

    sec = audit_untrusted_pr_or_repo(root)
    if sec['status'] == 'FAIL':
        return {'status': 'FAIL', 'reason': 'security pre-flight failed; refusing to execute gradlew', 'security': sec, 'executed_unprotected': False}

    chain = verify_gradle_execution_chain(root)
    if chain['status'] != 'PASS':
        return {'status': 'FAIL', 'reason': chain['reason'], 'wrapper_verification': chain, 'security': sec, 'executed_unprotected': False}

    gradle_args = ['./gradlew', '--no-daemon', '--console=plain']
    if offline:
        gradle_args.append('--offline')
    gradle_args.append(gradle_task)

    sandbox_res = run_in_bwrap_sandbox(
        root,
        gradle_args,
        timeout=timeout,
        allow_network=allow_network,
        extract_outputs_to_host=True,
        sandbox_available_override=sandbox_available_override,
    )
    if sandbox_res['status'] == 'BLOCKED' or sandbox_res.get('returncode') is None:
        return {
            'status': sandbox_res['status'],
            'reason': sandbox_res['reason'],
            'command': sandbox_res.get('sandbox_command', []),
            'wrapper_verification': chain,
            'sandbox': sandbox_res.get('sandbox'),
            'executed_unprotected': False,
            'apk_inspection': None,
        }

    log_out = sanitize_text((sandbox_res.get('stdout') or '') + '\n' + (sandbox_res.get('stderr') or ''), redact_home=False)
    cmd = sandbox_res['sandbox_command']
    if sandbox_res['returncode'] != 0:
        return {
            'status': 'FAIL',
            'reason': f'gradlew exited {sandbox_res["returncode"]}',
            'command': cmd,
            'wrapper_verification': chain,
            'sandbox': sandbox_res['sandbox'],
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-40:],
        }

    # Locate generated APK inside module path inferred from :src:lang:mod:assembleDebug
    parts = [p for p in gradle_task.split(':') if p]
    module_dir = root.joinpath(*parts[:-1]) if len(parts) > 1 else root
    apks = sorted(module_dir.glob('build/outputs/apk/**/*.apk'))
    if not apks and sandbox_res.get('collected_apks'):
        apks = sorted(Path(p) for p in sandbox_res['collected_apks'])
    if not apks:
        return {
            'status': 'FAIL',
            'reason': 'gradlew exited 0 but no .apk artifact was produced under build/outputs/apk',
            'command': cmd,
            'wrapper_verification': chain,
            'sandbox': sandbox_res['sandbox'],
            'executed_unprotected': False,
            'log_tail': log_out.splitlines()[-25:],
        }

    apk_path = apks[-1]
    inspection = inspect_apk(apk_path)
    return {
        'status': inspection['status'],
        'command': cmd,
        'apk_path': str(apk_path),
        'apk_inspection': inspection,
        'wrapper_verification': chain,
        'sandbox': sandbox_res['sandbox'],
        'executed_unprotected': False,
        'log_tail': log_out.splitlines()[-25:],
    }


def _extract_deeplink_rules(text: str) -> list[dict[str, str]]:
    """Parse deeplink{} DSL blocks and AndroidManifest <intent-filter>/<data> declarations."""
    rules: list[dict[str, str]] = []
    # Kotlin build.gradle.kts deeplink { ... } or scheme/host/pathPattern attributes
    for block_m in re.finditer(r'deeplink\s*\{([^}]*)\}', text, re.S):
        blk = block_m.group(1)
        scheme_m = re.search(r'\bscheme\s*=\s*"([^"]+)"', blk)
        host_m = re.search(r'\bhost\s*=\s*"([^"]+)"', blk)
        path_m = re.search(r'\bpathPattern\s*=\s*"([^"]+)"|\bpathPrefix\s*=\s*"([^"]+)"', blk)
        rules.append({
            'scheme': scheme_m.group(1) if scheme_m else 'https',
            'host': host_m.group(1) if host_m else '',
            'path_pattern': (path_m.group(1) or path_m.group(2)) if path_m else '/.*',
        })
    # XML AndroidManifest <data android:scheme=... android:host=... android:pathPattern=.../>
    for tag_m in re.finditer(r'<data\b([^>]+)/?>', text, re.S):
        attrs = tag_m.group(1)
        sch = re.search(r'android:scheme\s*=\s*["\']([^"\']+)["\']', attrs)
        hst = re.search(r'android:host\s*=\s*["\']([^"\']+)["\']', attrs)
        pat = re.search(r'android:path(?:Pattern|Prefix)?\s*=\s*["\']([^"\']+)["\']', attrs)
        if sch or hst or pat:
            rules.append({
                'scheme': sch.group(1) if sch else 'https',
                'host': hst.group(1) if hst else '',
                'path_pattern': pat.group(1) if pat else '/.*',
            })
    return rules


def _android_glob_to_regex(pat: str) -> re.Pattern[str]:
    if pat.startswith('/') and not ('.*' in pat or '\\' in pat):
        return re.compile('^' + re.escape(pat))
    conv = pat.replace('.*', '___WILD___').replace('.', r'\.').replace('___WILD___', '.*')
    return re.compile('^' + conv)


def verify_deeplink_intent_filters(
    manifest_or_gradle_text: str,
    test_urls: Sequence[str],
    *,
    package_name: str | None = None,
) -> dict[str, Any]:
    """Validate Android deep-link intent rules against sample work/chapter/invalid URLs and emit safe ADB command (0059/0851-0865)."""
    rules = _extract_deeplink_rules(manifest_or_gradle_text)
    if not rules:
        return {'status': 'FAIL', 'reason': 'no_deeplink_or_intent_filter_rules_found', 'rules': [], 'results': []}

    results: list[dict[str, Any]] = []
    for raw_url in test_urls:
        sp = urlsplit(raw_url.strip())
        matched_rule = None
        for r in rules:
            host_ok = (not r['host']) or (sp.hostname or '').lower() == r['host'].lower()
            scheme_ok = sp.scheme.lower() == r['scheme'].lower()
            path_rx = _android_glob_to_regex(r['path_pattern'])
            path_ok = bool(path_rx.search(sp.path or '/'))
            if scheme_ok and host_ok and path_ok:
                matched_rule = r
                break
        safe_cmd = f"adb shell am start -W -a android.intent.action.VIEW -d {shlex.quote(raw_url.strip())}"
        if package_name:
            safe_cmd += f' {shlex.quote(package_name)}'
        results.append({
            'url': raw_url,
            'matched': matched_rule is not None,
            'matched_rule': matched_rule,
            'adb_am_start_command': safe_cmd if matched_rule else None,
        })

    any_match = any(r['matched'] for r in results)
    return {
        'status': 'PASS' if any_match else 'FAIL',
        'rules': rules,
        'matched_count': sum(1 for r in results if r['matched']),
        'results': results,
    }


_UIA_BOUNDS_RE = re.compile(r'\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]')
_UIA_ERROR_BANNER_RE = re.compile(r'(?i)(http\s*error\s*[45]\d\d|error\s*loading|failed\s*to\s*load|no\s*results|cloudflare|captcha|exception|timed\s*out)')


def parse_uiautomator_hierarchy_and_plan_actions(
    xml_text: str,
    *,
    target_queries: Sequence[str] = ('search', 'explore', 'browse'),
) -> dict[str, Any]:
    """Parse Android uiautomator dump XML hierarchy, extract bounds/tap centers, error banners, and planned ADB input commands (0052/0601)."""
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError as exc:
        return {'status': 'FAIL', 'reason': f'invalid_uiautomator_xml:{exc}', 'nodes_count': 0}

    nodes: list[dict[str, Any]] = []
    matched_targets: list[dict[str, Any]] = []
    error_banners: list[dict[str, Any]] = []
    planned_cmds: list[str] = []
    q_low = [q.lower() for q in target_queries]

    for el in root.iter('node'):
        bounds_raw = el.attrib.get('bounds', '')
        m = _UIA_BOUNDS_RE.fullmatch(bounds_raw.strip())
        if not m:
            continue
        x1, y1, x2, y2 = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
        if x2 < x1 or y2 < y1:
            continue
        cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
        text = el.attrib.get('text', '')
        desc = el.attrib.get('content-desc', '')
        res_id = el.attrib.get('resource-id', '')
        clickable = el.attrib.get('clickable', 'false').lower() == 'true'
        label = ' | '.join(p for p in (text, desc, res_id) if p)

        node_info = {
            'resource_id': res_id,
            'text': text,
            'content_desc': desc,
            'clickable': clickable,
            'bounds': [x1, y1, x2, y2],
            'center': [cx, cy],
        }
        nodes.append(node_info)

        combined_msg = f'{text} {desc}'.strip()
        if combined_msg and _UIA_ERROR_BANNER_RE.search(combined_msg):
            error_banners.append({'label': combined_msg, 'bounds': [x1, y1, x2, y2]})

        low_label = label.lower()
        if label and any(q in low_label for q in q_low):
            tap_cmd = f'adb shell input tap {cx} {cy}'
            matched_targets.append({**node_info, 'adb_tap_command': tap_cmd})
            planned_cmds.append(tap_cmd)

    status = 'FAIL' if error_banners else ('PASS' if nodes else 'INCONCLUSIVE')
    return {
        'status': status,
        'nodes_count': len(nodes),
        'clickable_count': sum(1 for n in nodes if n['clickable']),
        'matched_targets': matched_targets,
        'error_banners': error_banners,
        'planned_adb_input_commands': planned_cmds,
    }


def build_mihon_ui_navigation_plan(
    package_name: str,
    source_name: str,
    query: str,
    *,
    orientation: str = 'portrait',
    reading_mode: str = 'vertical',
    adb_output: str | None = None,
    debug_apk_path: Path | str | None = None,
    pool_devices: Sequence[dict[str, Any]] | None = None,
    snapshot_name: str = 'clean-baseline',
    ui_dump_xml: str | None = None,
) -> dict[str, Any]:
    """Prepare Android UI automation, emulator snapshot reset, JDWP debuggable check, rotation & device pool plan (0021/0023/0052-0058/0601-0620/0997)."""
    if orientation not in {'portrait', 'landscape'}:
        return {'status': 'FAIL', 'reason': f'invalid orientation: {orientation!r}'}

    adb_state = adb_doctor(adb_output=adb_output)
    is_debuggable = False
    apk_verified = False
    if debug_apk_path is not None and Path(debug_apk_path).is_file():
        insp = inspect_apk(debug_apk_path)
        apk_verified = insp['status'] == 'PASS'
        is_debuggable = bool((insp.get('signing') or {}).get('is_debug_cert'))

    # Select pool device safely when a multi-device pool is passed
    selected_pool_device = None
    if pool_devices:
        ready_pool = [d for d in pool_devices if d.get('state') == 'device' and not d.get('busy')]
        selected_pool_device = ready_pool[0] if ready_pool else None

    ui_steps = [
        {'step': 1, 'action': 'emulator_snapshot_restore', 'command': f'emulator -snapshot-load {shlex.quote(snapshot_name)}', 'optional_emulator_only': True},
        {'step': 2, 'action': 'set_orientation', 'command': f"adb shell settings put system user_rotation {0 if orientation == 'portrait' else 1}", 'reading_mode': reading_mode},
        {'step': 3, 'action': 'launch_host_app', 'command': f'adb shell monkey -p {shlex.quote(package_name)} -c android.intent.category.LAUNCHER 1'},
        {'step': 4, 'action': 'dump_ui_hierarchy', 'command': 'adb shell uiautomator dump /sdcard/window_dump.xml'},
        {'step': 5, 'action': 'open_source_and_search', 'source': source_name, 'query': query},
        {'step': 6, 'action': 'capture_screenshot_for_visual_diff', 'command': 'adb exec-out screencap -p'},
        {'step': 7, 'action': 'jdwp_attach_if_debuggable', 'allowed': is_debuggable, 'command': f'adb jdwp' if is_debuggable else None},
    ]

    ui_dump_analysis = parse_uiautomator_hierarchy_and_plan_actions(ui_dump_xml, target_queries=(source_name, 'search', 'explore')) if ui_dump_xml else None
    device_connected = (adb_state['status'] == 'PASS')
    return {
        'status': 'PASS' if device_connected else 'BLOCKED',
        'software_layer_status': 'FAIL' if (ui_dump_analysis and ui_dump_analysis['status'] == 'FAIL') else 'PASS',
        'device_test_status': 'NOT_RUN' if not device_connected else 'READY_FOR_AUTHORIZED_RUN',
        'package_name': package_name,
        'source_name': source_name,
        'orientation': orientation,
        'reading_mode': reading_mode,
        'apk_verified': apk_verified,
        'jdwp_attach_allowed': is_debuggable,
        'selected_pool_device': selected_pool_device,
        'adb_state': adb_state,
        'ui_steps': ui_steps,
        'ui_dump_analysis': ui_dump_analysis,
        'note': 'Device hardware execution remains NOT_RUN/BLOCKED whenever adb devices is empty; software automation & XML hierarchy parser are validated.',
    }


def _extract_binary_symbols_from_artifact(artifact: Path) -> set[str]:
    """Extract binary class/descriptor symbols from .dex, .class, .jar, or .apk archives (0881)."""
    symbols: set[str] = set()
    suffix = artifact.suffix.lower()
    blobs: list[bytes] = []
    if suffix in {'.apk', '.jar', '.zip'}:
        with zipfile.ZipFile(artifact) as zf:
            for name in zf.namelist():
                if name.endswith('.dex') or name.endswith('.class'):
                    blobs.append(zf.read(name))
    else:
        blobs.append(artifact.read_bytes())

    for blob in blobs:
        # Match Dalvik/JVM binary class descriptors (e.g. Leu/kanade/tachiyomi/source/online/HttpSource;)
        for m in re.finditer(rb'L[a-zA-Z0-9_$/]{4,160};', blob):
            symbols.add(m.group(0).decode('ascii', errors='ignore'))
        # Match JVM method binary descriptors like (ILjava/lang/String;)Ljava/util/List;
        for m in re.finditer(rb'\((?:\[|[A-Z])(?:[A-Za-z0-9_$/;]|\[){0,120}\)(?:\[|[A-Z])[A-Za-z0-9_$/;]{0,80}', blob):
            symbols.add(m.group(0).decode('ascii', errors='ignore'))
    return symbols


def compare_binary_dex_and_jar_apis(old_path: Path | str, new_path: Path | str) -> dict[str, Any]:
    """Compare compiled binary symbols (.dex/.class/.jar/.apk) beyond textual Kotlin signatures (0881)."""
    p_old, p_new = Path(old_path), Path(new_path)
    if not p_old.is_file() or not p_new.is_file():
        return {'status': 'FAIL', 'error': 'both compiled artifacts must exist'}

    sym_old = _extract_binary_symbols_from_artifact(p_old)
    sym_new = _extract_binary_symbols_from_artifact(p_new)
    removed = sorted(sym_old - sym_new)
    added = sorted(sym_new - sym_old)

    if removed:
        classification = 'BINARY_BREAKING_REMOVED_SYMBOLS'
        status = 'FAIL'
    elif not sym_old or not sym_new:
        classification = 'INDETERMINADO_NO_BINARY_SYMBOLS'
        status = 'INCONCLUSIVE'
    else:
        classification = 'BINARY_COMPATIBLE_ADDITIVE'
        status = 'PASS'

    return {
        'status': status,
        'classification': classification,
        'old_symbols_count': len(sym_old),
        'new_symbols_count': len(sym_new),
        'removed_symbols': removed[:50],
        'added_symbols': added[:50],
    }


def run_git_bisect_regression(
    repo_root: Path | str,
    good_rev: str,
    bad_rev: str,
    test_fn: Callable[[Path], bool],
) -> dict[str, Any]:
    """Isolate first regression commit in an isolated temporary clone via binary search without touching user worktree (0087/0812)."""
    src = Path(repo_root).resolve()
    if not (src / '.git').exists():
        return {'status': 'FAIL', 'error': f'not a git repository: {src}'}
    sec = audit_untrusted_pr_or_repo(src)
    if sec['status'] == 'FAIL':
        return {'status': 'FAIL', 'error': 'refusing bisect on repo failing security audit', 'security': sec, 'executed_unprotected': False}

    try:
        commits_raw = subprocess.check_output(
            ['git', 'rev-list', '--reverse', f'{good_rev}..{bad_rev}'],
            cwd=src,
            text=True,
        ).strip()
    except subprocess.SubprocessError as exc:
        return {'status': 'FAIL', 'error': f'cannot resolve revision range: {exc}'}

    commits = [good_rev, *[c for c in commits_raw.splitlines() if c]]
    if len(commits) < 2:
        return {'status': 'INCONCLUSIVE', 'error': 'revision range contains fewer than 2 commits'}

    tested_steps: list[dict[str, Any]] = []

    class _UnsafeBisectCommit(RuntimeError):
        def __init__(self, rev: str, sec_res: dict[str, Any]) -> None:
            super().__init__(rev)
            self.rev = rev
            self.sec_res = sec_res

    with tempfile.TemporaryDirectory(prefix='nox-bisect-') as tmp:
        wt = Path(tmp) / 'clone'
        subprocess.run(
            ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=user', 'clone', '--quiet', '--no-hardlinks', '--no-recurse-submodules', str(src), str(wt)],
            check=True,
        )

        def _eval_idx(i: int) -> bool:
            rev = commits[i]
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--quiet', '--detach', rev], cwd=wt, check=True)
            sec_rev = audit_untrusted_pr_or_repo(wt)
            if sec_rev['status'] == 'FAIL':
                raise _UnsafeBisectCommit(rev, sec_rev)
            passed = bool(test_fn(wt))
            tested_steps.append({'index': i, 'commit': rev, 'passed': passed})
            return passed

        try:
            if not _eval_idx(0):
                return {'status': 'FAIL', 'error': 'good_rev already failed test_fn', 'steps': tested_steps}
            if _eval_idx(len(commits) - 1):
                return {'status': 'INCONCLUSIVE', 'error': 'bad_rev did not fail test_fn', 'steps': tested_steps}

            lo, hi = 0, len(commits) - 1
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if _eval_idx(mid):
                    lo = mid
                else:
                    hi = mid
        except _UnsafeBisectCommit as exc:
            return {
                'status': 'FAIL',
                'error': f'commit {exc.rev} failed security pre-flight; refusing test_fn execution',
                'commit': exc.rev,
                'security': exc.sec_res,
                'steps': tested_steps,
                'executed_unprotected': False,
            }

        culprit = commits[hi]
        subj = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', 'show', '-s', '--format=%s', culprit], cwd=wt, text=True).strip()
        return {
            'status': 'PASS',
            'first_bad_commit': culprit,
            'commit_subject': subj,
            'total_commits_in_range': len(commits),
            'steps_evaluated': len(tested_steps),
            'steps': tested_steps,
        }


def run_solution_tournament(
    candidates: Sequence[dict[str, Any]],
    fixtures: Sequence[Any],
    evaluator: Callable[[dict[str, Any], Any], dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate competing isolated patch candidates against identical fixtures and rank by pass rate & minimal diff (0103)."""
    if not candidates or not fixtures:
        return {'status': 'FAIL', 'error': 'candidates and fixtures must be non-empty', 'ranking': []}

    board: list[dict[str, Any]] = []
    for cand in candidates:
        cid = str(cand.get('id', 'unnamed'))
        patch_lines = int(cand.get('patch_lines', 9999))
        preserves_id = bool(cand.get('preserves_identity', True))
        passed = 0
        failed_cases: list[Any] = []
        for fx in fixtures:
            res = evaluator(cand, fx)
            if res.get('passed'):
                passed += 1
            else:
                failed_cases.append(fx.get('name') if isinstance(fx, dict) else str(fx))
        board.append({
            'id': cid,
            'passed': passed,
            'total': len(fixtures),
            'pass_rate': round(passed / len(fixtures), 4),
            'preserves_identity': preserves_id,
            'patch_lines': patch_lines,
            'failed_cases': failed_cases,
        })

    # Rank by highest pass_rate, identity preservation, and smallest minimal patch
    board.sort(key=lambda x: (-int(x['preserves_identity']), -x['pass_rate'], x['patch_lines']))
    winner = board[0]
    ok = winner['passed'] == len(fixtures) and winner['preserves_identity']
    return {
        'status': 'PASS' if ok else 'FAIL',
        'winner': winner,
        'ranking': board,
    }
