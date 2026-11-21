#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Agent-independent CLI for Nox Extension Developer."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import api_compare  # noqa: E402
import nox_android  # noqa: E402
import nox_core  # noqa: E402
import nox_enhancements  # noqa: E402
import nox_env  # noqa: E402
import nox_issues  # noqa: E402
import nox_lab  # noqa: E402
import nox_matrix  # noqa: E402
import nox_scaffold  # noqa: E402
import references  # noqa: E402


def _exit_code_for_status(status: str) -> int:
    if status == 'PASS' or status in {'verified', 'verified_cached', 'COMPATIVEL_NO_ESCOPO_DECLARADO'}:
        return 0
    if status in {'BLOCKED', 'INCONCLUSIVE', 'NOT_RUN', 'offline_or_unverified', 'INDETERMINADO', 'MISSING'}:
        return 2
    return 1


def _emit(payload: dict[str, Any], *, as_json: bool = True, beginner: bool = False, lang: str = 'pt-BR') -> None:
    if as_json and not beginner:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    status = payload.get('status') or payload.get('overall_status') or 'UNKNOWN'
    eff_lang = payload.get('ui_lang') or lang or 'pt-BR'
    is_en = eff_lang == 'en'
    if payload.get('user_message'):
        print(payload['user_message'])
        if payload.get('limitations') and not payload.get('apk_ready'):
            for lim in payload['limitations']:
                if not any(tok in str(lim) for tok in ('{', 'Traceback', './gradlew', 'K2JVMCompiler', 'bwrap')):
                    print(f'- {lim}')
        if payload.get('apk_ready') and payload.get('apk_options'):
            print()
            if payload.get('next_step'):
                print(payload['next_step'])
            for opt in payload['apk_options']:
                print(opt['label'])
        elif payload.get('next_step'):
            print(payload['next_step'])
        return

    if not is_en:
        print(f'Status: {status}')
        if payload.get('guidance'):
            print(f"Próximo passo: {payload['guidance']}")
        if payload.get('issues'):
            print(f"Problemas detectados ({len(payload['issues'])}): {', '.join(str(x) for x in payload['issues'][:5])}")
    else:
        print(f'Status: {status}')
        if payload.get('guidance'):
            print(f"Next step: {payload['guidance']}")
        if payload.get('issues'):
            print(f"Detected issues ({len(payload['issues'])}): {', '.join(str(x) for x in payload['issues'][:5])}")


class _TechnicalModeAction(argparse.Action):
    """Enable full technical JSON output and disable simplified beginner prose mode."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        setattr(namespace, self.dest, True)
        setattr(namespace, 'beginner', False)
        setattr(namespace, 'json', True)


def _attach_global_flags_recursive(parser: argparse.ArgumentParser, *, is_root: bool = False) -> None:
    """Propagate global UI/mode flags into every subparser and nested subparser without breaking scaffold --lang."""
    if not is_root:
        existing = parser._option_string_actions
        if '--json' not in existing:
            parser.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='emit machine-readable JSON (default)')
        if '--beginner' not in existing:
            parser.add_argument('--beginner', action='store_true', default=argparse.SUPPRESS, help='emit short beginner-friendly summary')
        if '--technical' not in existing:
            parser.add_argument('--technical', nargs=0, action=_TechnicalModeAction, default=argparse.SUPPRESS, help='emit full technical JSON details')
        if '--dry-run' not in existing:
            parser.add_argument('--dry-run', action='store_true', default=argparse.SUPPRESS, help='inspect without modifying persistent files')
        if '--lang' not in existing:
            parser.add_argument('--lang', choices=['pt-BR', 'en'], default=argparse.SUPPRESS, help='output language for summaries')
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            seen: set[int] = set()
            for sub_p in action.choices.values():
                if id(sub_p) not in seen:
                    seen.add(id(sub_p))
                    _attach_global_flags_recursive(sub_p, is_root=False)


def build_parser() -> argparse.ArgumentParser:
    p = _build_raw_parser()
    sub_action = next((a for a in p._actions if isinstance(a, argparse._SubParsersAction)), None)
    if sub_action is not None:
        au = sub_action.add_parser('auto', help='automatically route plain-language request or repair task')
        au.add_argument('prompt', nargs='*', help='plain-language request or website URL')
        au.add_argument('--target', type=Path, help='optional local extension path to diagnose/fix')
        au.add_argument('--symptom', default='broken source or loading error', help='symptom description when repairing')
        au.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'])
        au.add_argument('--name', help='optional extension name override')
        au.add_argument('--output', type=Path, help='optional destination folder for scaffolded files')
        au.add_argument('--repo', type=Path, help='optional repository root for duplicate/existing search')
        au.add_argument('--build-task', help='optional Gradle task to run inside Bubblewrap sandbox')
        au.add_argument('--site-url', help='explicit website base URL override')
        au.add_argument('--allow-local-fixture', action='store_true', help='allow loopback fixture servers (127.0.0.1/localhost)')

        ac = sub_action.add_parser('auto-create', help='beginner-first automated extension creation flow')
        ac.add_argument('prompt', nargs='+', help='plain-language description or target website URL')
        ac.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'])
        ac.add_argument('--name', help='optional extension name override')
        ac.add_argument('--source-lang', default='pt-BR', help='extension source language (default: pt-BR)')
        ac.add_argument('--output', type=Path, help='optional destination folder for scaffolded files')
        ac.add_argument('--repo', type=Path, help='optional repository root')
        ac.add_argument('--build-task', help='optional Gradle task to run inside Bubblewrap sandbox')
        ac.add_argument('--site-url', help='explicit website base URL override')
        ac.add_argument('--allow-local-fixture', action='store_true', help='allow loopback fixture servers (127.0.0.1/localhost)')

        af = sub_action.add_parser('auto-fix', help='automated diagnosis, loop-detection, and adaptive repair guidance')
        af.add_argument('target', type=Path, help='local extension directory or source file')
        af.add_argument('--symptom', default='broken source or loading error', help='symptom or user complaint')
        af.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'])
        af.add_argument('--build-task', help='optional Gradle task to compile in Bubblewrap sandbox')
        af.add_argument('--attempts-json', type=Path, help='optional JSON file listing previous troubleshooting attempts')
        af.add_argument('--site-url', help='explicit website base URL override')
        af.add_argument('--allow-local-fixture', action='store_true', help='allow loopback fixture servers (127.0.0.1/localhost)')

        ad = sub_action.add_parser('apk-deliver', help='execute post-build APK delivery choice (1=save, 2=adb install/test, 3=keep)')
        ad.add_argument('apk', type=Path, help='path to freshly compiled Debug APK')
        ad.add_argument('--choice', required=True, help='1/save, 2/adb, or 3/keep')
        ad.add_argument('--dest', type=Path, help='destination folder or APK file path when choice is save')
        ad.add_argument('--overwrite', action='store_true', help='authorize overwriting an existing destination APK')
        ad.add_argument('--serial', help='optional ADB device serial when multiple devices are connected')
        ad.add_argument('--authorize-install', action='store_true', help='explicit user confirmation before adb install')
        ad.add_argument('--expected-package', help='optional expected Android package name')

    _attach_global_flags_recursive(p, is_root=True)
    return p


def _build_raw_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='nox', description='Nox Extension Developer local engineering CLI')
    p.add_argument('--json', action='store_true', default=True, help='emit machine-readable JSON (default)')
    p.add_argument('--beginner', action='store_true', help='emit short beginner-friendly summary')
    p.add_argument('--technical', nargs=0, action=_TechnicalModeAction, default=False, help='emit full technical JSON details')
    p.add_argument('--lang', choices=['pt-BR', 'en'], default=None, help='output language for summaries (auto-detected when omitted)')
    p.add_argument('--dry-run', action='store_true', help='inspect without modifying persistent files')

    sub = p.add_subparsers(dest='command', required=True)

    # doctor
    d = sub.add_parser('doctor', help='check Python, Git, JDK, Node, Android SDK, and ADB readiness')
    d.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'], default=None)
    d.add_argument('--path', type=Path, default=None)

    # skill-status
    sub.add_parser('skill-status', help='check where agent skill installation paths point vs canonical repo')

    # inspect
    ins = sub.add_parser('inspect', help='detect ecosystem, modern/legacy architecture, and source IDs')
    ins.add_argument('target', type=Path)

    # search-existing
    se = sub.add_parser('search-existing', help='search repo for existing extensions, multisrc themes, and shared libs')
    se.add_argument('repo', type=Path)
    se.add_argument('query', help='site name, domain, or theme name')

    # api-binary-compare
    abc = sub.add_parser('api-binary-compare', help='compare compiled binary DEX/JAR/APK symbols')
    abc.add_argument('old', type=Path)
    abc.add_argument('new', type=Path)

    # deeplink-check
    dlc = sub.add_parser('deeplink-check', help='validate Android intent-filter/deeplink rules against URLs')
    dlc.add_argument('file', type=Path)
    dlc.add_argument('urls', nargs='+')

    # enhance
    enh = sub.add_parser('enhance', help='list enhancements 1026..1200 or audit source files on demand')
    enh.add_argument('--list', action='store_true')
    enh.add_argument('--audit-source', type=Path, default=None)
    enh.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'], default='keiyoushi')

    # autofix-diagnose
    afd = sub.add_parser('autofix-diagnose', help='correlate symptom with local project inspection & multi-ecosystem PR precedents')
    afd.add_argument('target', type=Path)
    afd.add_argument('--symptom', required=True)
    afd.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'], default=None)

    # review-council
    rc = sub.add_parser('review-council', help='run on-demand 4-perspective real review council on an extension project or file')
    rc.add_argument('target', type=Path)
    rc.add_argument('--enabled', action='store_true')
    rc.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'], default=None)

    # bisect
    bs = sub.add_parser('bisect', help='binary search first regression commit in isolated clone')
    bs.add_argument('repo', type=Path)
    bs.add_argument('good')
    bs.add_argument('bad')
    bs.add_argument('--test-cmd', required=True, help='command executed inside checked out commit clone')

    # scaffold
    sc = sub.add_parser('scaffold', help='generate minimal official-pattern source files for Keiyoushi/Yuzono/LNReader')
    sc.add_argument('ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'])
    sc.add_argument('--name', required=True)
    sc.add_argument('--base-url', required=True)
    sc.add_argument('--lang', default='en')
    sc.add_argument('--out', type=Path, required=True)

    # scenarios
    sub.add_parser('scenarios', help='run end-to-end HTTP local creation/repair/update scenarios (A/B/C)')

    # build
    bld = sub.add_parser('build', help='audit repo security, run gradlew assembleDebug, and inspect APK')
    bld.add_argument('repo', type=Path)
    bld.add_argument('task', help='e.g. :src:all:noxsandboxanime:assembleDebug')
    bld.add_argument('--offline', action='store_true')
    bld.add_argument('--timeout', type=int, default=300)

    # references
    ref_p = sub.add_parser('references', help='sync or check commit-pinned upstream references')
    ref_p.add_argument('action', choices=['sync', 'status'])
    ref_p.add_argument('ecosystem', choices=sorted(references.SOURCES))

    # api-compare
    ac = sub.add_parser('api-compare', help='compare scoped API contracts or source files')
    ac.add_argument('old', type=Path)
    ac.add_argument('new', type=Path)
    ac.add_argument('--extract', choices=sorted(api_compare.ECOSYSTEMS))
    ac.add_argument('--structural', action='store_true')

    # site-inspect
    si = sub.add_parser('site-inspect', help='analyze site HTML/JSON fixture for platform, JS/SPA, and blocks')
    si.add_argument('file', type=Path)
    si.add_argument('--url', default=None)
    si.add_argument('--status-code', type=int, default=200)
    si.add_argument('--expected', choices=['html', 'json'], default='html')

    # lab
    lab = sub.add_parser('lab', help='run image/manga/anime/novel/search functional lab checks')
    lab_sub = lab.add_subparsers(dest='lab_cmd', required=True)
    li = lab_sub.add_parser('image', help='verify image magic bytes, dimensions, and fake 200 HTML')
    li.add_argument('file', type=Path)
    li.add_argument('--content-type', default=None)
    li.add_argument('--url', default=None)
    lm = lab_sub.add_parser('manga', help='validate manga chapters JSON fixture')
    lm.add_argument('file', type=Path)
    la = lab_sub.add_parser('anime', help='validate anime episodes/hosters/videos JSON fixture')
    la.add_argument('file', type=Path)
    ln = lab_sub.add_parser('novel', help='validate novel metadata and chapter HTML fixture')
    ln.add_argument('file', type=Path)
    ls = lab_sub.add_parser('search', help='validate positive search and pagination fixture')
    ls.add_argument('file', type=Path)
    lvd = lab_sub.add_parser('visual-diff', help='compare before/after screenshots with optional PII box redaction')
    lvd.add_argument('before', type=Path)
    lvd.add_argument('after', type=Path)
    lmd = lab_sub.add_parser('metadata', help='extract smart work metadata ignoring ad/nav clutter')
    lmd.add_argument('file', type=Path)
    lms = lab_sub.add_parser('map-site', help='map image CDN hosts and functional site routes')
    lms.add_argument('file', type=Path)
    lms.add_argument('--base-url', required=True)
    ldsh = lab_sub.add_parser('dash', help='inspect DASH MPD or WebVTT/SRT/ASS subtitles')
    ldsh.add_argument('file', type=Path)
    ldsh.add_argument('--kind', choices=['mpd', 'vtt', 'srt', 'ass'], default='mpd')

    # issues
    iss = sub.add_parser('issues', help='classify PR/issue evidence, inspect PR diffs, or verify historical Keiyoushi proofs')
    iss_sub = iss.add_subparsers(dest='iss_cmd', required=True)
    ic = iss_sub.add_parser('classify', help='classify an issue/PR JSON record')
    ic.add_argument('file', type=Path)
    ico = iss_sub.add_parser('correlate', help='correlate observed signals JSON into falsifiable hypotheses')
    ico.add_argument('file', type=Path)
    ico.add_argument('--ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'], default=None)
    ife = iss_sub.add_parser('fetch', help='query real GitHub issues/PRs for keiyoushi/yuzono/lnreader')
    ife.add_argument('ecosystem', choices=['keiyoushi', 'yuzono', 'lnreader'])
    ife.add_argument('--query', default=None)
    ife.add_argument('--limit', type=int, default=6)
    ife.add_argument('--out', type=Path, default=None)
    ivh = iss_sub.add_parser('verify-historical', help='verify historical Keiyoushi PR diffs & executable adaptation proofs')
    ivh.add_argument('--out', type=Path, default=None)

    # apk-inspect
    apk = sub.add_parser('apk-inspect', help='inspect APK metadata, SHA-256, signing certs, and optional index')
    apk.add_argument('apk', type=Path)
    apk.add_argument('--index', type=Path, default=None)
    apk.add_argument('--expected-package', default=None)

    # adb
    adb = sub.add_parser('adb', help='non-destructive ADB device check, UI plan, and logcat filter')
    adb_sub = adb.add_subparsers(dest='adb_cmd', required=True)
    ad = adb_sub.add_parser('doctor', help='check USB/Wi-Fi ADB device state')
    ad.add_argument('--serial', default=None)
    af = adb_sub.add_parser('filter-logcat', help='filter a logcat file by package/PID and redact secrets')
    af.add_argument('file', type=Path)
    af.add_argument('--package', default=None)
    af.add_argument('--pid', type=int, default=None)
    aui = adb_sub.add_parser('ui-plan', help='generate & validate Mihon UI automation + orientation + snapshot plan')
    aui.add_argument('--package', required=True)
    aui.add_argument('--source', required=True)
    aui.add_argument('--query', required=True)
    aui.add_argument('--orientation', choices=['portrait', 'landscape'], default='portrait')

    # security-audit
    sec = sub.add_parser('security-audit', help='audit untrusted repo/PR for Gradle RCE, workflows, secrets, and symlinks')
    sec.add_argument('target', type=Path)

    # report
    rep = sub.add_parser('report', help='audit receipts & unsupported claims in a verification report JSON')
    rep.add_argument('file', type=Path)

    # verify-report
    vr = sub.add_parser('verify-report', help='verify paths and sha256sums referenced by a Markdown audit report')
    vr.add_argument('report', type=Path)
    vr.add_argument('--root', type=Path, default=SCRIPTS_DIR.parent)

    # benchmark
    sub.add_parser('benchmark', help='run reproducible dev + blind benchmark comparing v1.0.3 vs v2.0.0')

    # matrix
    mat = sub.add_parser('matrix', help='query or validate the 0001..1200 traceability matrix')
    mat.add_argument('--validate', action='store_true')
    mat.add_argument('--summary', action='store_true')
    mat.add_argument('--id', default=None)
    mat.add_argument('--rebuild', action='store_true', help='regenerate matrix artifacts from prompt file')

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command

    if cmd == 'doctor':
        res = nox_env.run_doctor(args.ecosystem, check_path=args.path)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'skill-status':
        res = nox_env.check_skill_installations(SCRIPTS_DIR.parent)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'inspect':
        res = nox_env.inspect_project(args.target)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'search-existing':
        res = nox_env.search_existing_extensions(args.repo, args.query)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'api-binary-compare':
        res = nox_android.compare_binary_dex_and_jar_apis(args.old, args.new)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'deeplink-check':
        res = nox_android.verify_deeplink_intent_filters(args.file.read_text(encoding='utf-8', errors='replace'), args.urls)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'enhance':
        if args.audit_source is not None:
            res = nox_enhancements.audit_source_file_on_demand(args.audit_source, ecosystem=args.ecosystem)
        else:
            res = {
                'status': 'PASS',
                'count': len(nox_enhancements.ENHANCEMENT_REGISTRY),
                'items': [{'id': v['id'], 'category': v['category'], 'title': v['title'], 'function': v['function']} for v in nox_enhancements.ENHANCEMENT_REGISTRY.values()],
            }
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])

    if cmd == 'autofix-diagnose':
        res = nox_issues.diagnose_and_suggest_fix_from_issues(args.target, args.symptom, ecosystem=args.ecosystem)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])

    if cmd == 'review-council':
        res = nox_issues.run_multi_agent_review_council(target_path=args.target, enabled=args.enabled, ecosystem=args.ecosystem)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])

    if cmd == 'scaffold':
        if args.dry_run:
            res = {'status': 'NOT_RUN', 'dry_run': True, 'ecosystem': args.ecosystem, 'name': args.name}
        else:
            res = nox_scaffold.scaffold_extension(args.ecosystem, args.name, args.base_url, lang=args.lang_code if hasattr(args, 'lang_code') else args.lang, output_dir=args.out)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'scenarios':
        res = nox_scaffold.run_functional_scenarios()
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'build':
        if args.dry_run:
            res = {'status': 'NOT_RUN', 'dry_run': True, 'repo': str(args.repo), 'task': args.task}
        else:
            res = nox_android.build_debug_apk(args.repo, args.task, timeout=args.timeout, offline=args.offline)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'references':
        cache = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'opencode/nox-workspace/nox-extension-developer'
        if args.action == 'status':
            res = references.status(args.ecosystem, cache)
        elif args.dry_run:
            res = {'status': 'NOT_RUN', 'dry_run': True, 'action': f'references sync {args.ecosystem}'}
        else:
            res = references.sync(args.ecosystem, cache)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'api-compare':
        if args.extract:
            ext = api_compare.extract_structural if args.structural else api_compare.extract
            old = ext(args.old.read_text(encoding='utf-8'), args.extract, 'source-comparison')
            new = ext(args.new.read_text(encoding='utf-8'), args.extract, 'source-comparison')
            res = api_compare.compare(old, new)
        else:
            res = api_compare.compare(json.loads(args.old.read_text()), json.loads(args.new.read_text()))
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['classification'])

    if cmd == 'site-inspect':
        body = args.file.read_text(encoding='utf-8', errors='replace')
        res = nox_lab.analyze_site_dna(body, status_code=args.status_code, url=args.url, expected_kind=args.expected)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'lab':
        if args.lab_cmd == 'image':
            res = nox_lab.inspect_image_payload(args.file.read_bytes(), content_type=args.content_type, url=args.url)
        elif args.lab_cmd == 'visual-diff':
            res = nox_lab.compare_visual_captures(args.before.read_bytes(), args.after.read_bytes())
        elif args.lab_cmd == 'metadata':
            res = nox_lab.extract_smart_metadata(args.file.read_text(encoding='utf-8', errors='replace'))
        elif args.lab_cmd == 'map-site':
            res = nox_lab.map_image_servers_and_routes(args.file.read_text(encoding='utf-8', errors='replace'), args.base_url)
        elif args.lab_cmd == 'dash':
            res = nox_lab.inspect_dash_and_subtitles(args.file.read_text(encoding='utf-8', errors='replace'), kind=args.kind)
        else:
            data = json.loads(args.file.read_text(encoding='utf-8'))
            if args.lab_cmd == 'manga':
                res = nox_lab.audit_manga_content(data.get('manga', {}), data.get('chapters', []))
            elif args.lab_cmd == 'anime':
                res = nox_lab.audit_anime_content(data.get('anime', {}), data.get('episodes', []), data.get('hosters', []), data.get('videos', []))
            elif args.lab_cmd == 'novel':
                res = nox_lab.audit_novel_content(data.get('novel', {}), data.get('chapters', []), data.get('chapter_html', ''))
            else:
                res = nox_lab.audit_search_and_pagination(
                    data.get('query', ''),
                    data.get('results', []),
                    expected_title_substr=data.get('expected_title_substr'),
                    popular_results=data.get('popular_results'),
                    page1_results=data.get('page1_results'),
                    page2_results=data.get('page2_results'),
                    has_next_page=bool(data.get('has_next_page', False)),
                )
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'issues':
        if args.iss_cmd == 'fetch':
            res = nox_issues.fetch_ecosystem_issues_and_prs(args.ecosystem, query=args.query, limit=args.limit, cache_out=args.out)
            _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
            return _exit_code_for_status(res['status'])
        if args.iss_cmd == 'verify-historical':
            res = nox_issues.verify_historical_keiyoushi_cases()
            if args.out:
                args.out.write_text(json.dumps(res, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
            _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
            return _exit_code_for_status(res['status'])
        data = json.loads(args.file.read_text(encoding='utf-8'))
        if args.iss_cmd == 'classify':
            res = nox_issues.classify_issue_pr_record(data)
            _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
            return 0 if res['usable_as_proven_fix'] else 2
        res = nox_issues.correlate_symptoms(data, ecosystem=args.ecosystem)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'apk-inspect':
        res = nox_android.inspect_apk(args.apk, index_json_path=args.index, expected_package=args.expected_package)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'adb':
        if args.adb_cmd == 'doctor':
            res = nox_android.adb_doctor(selected_serial=args.serial)
        elif args.adb_cmd == 'ui-plan':
            res = nox_android.build_mihon_ui_navigation_plan(args.package, args.source, args.query, orientation=args.orientation)
        else:
            res = nox_android.parse_and_filter_logcat(args.file.read_text(encoding='utf-8', errors='replace'), target_package=args.package, target_pid=args.pid)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'security-audit':
        pr_res = nox_android.audit_untrusted_pr_or_repo(args.target)
        git_res = nox_env.audit_git_safety(args.target)
        status = 'FAIL' if (pr_res['status'] == 'FAIL' or git_res['status'] == 'FAIL') else 'PASS'
        res = {'status': status, 'pr_supply_chain': pr_res, 'git_safety': git_res}
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(status)

    if cmd == 'report':
        data = json.loads(args.file.read_text(encoding='utf-8'))
        agg = nox_core.aggregate_status(data.get('receipts') or [])
        unsupported = nox_core.detect_unsupported_claims(data)
        status = 'FAIL' if unsupported else agg['overall_status']
        res = {'status': status, 'aggregation': agg, 'unsupported_claims': unsupported}
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(status)

    if cmd == 'verify-report':
        res = nox_core.verify_report_claims(args.report, args.root)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'benchmark':
        res = nox_matrix.run_benchmark()
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])


    if cmd == 'matrix':
        if args.rebuild and not args.dry_run:
            res = nox_matrix.write_matrix_artifacts()
        elif args.id:
            mat = nox_matrix.load_matrix()
            hit = next((it for it in mat['items'] if it['id'] == args.id.zfill(4)), None)
            res = {'status': 'PASS', 'item': hit} if hit else {'status': 'FAIL', 'error': f'ID {args.id} not found'}
        else:
            res = nox_matrix.validate_matrix()
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])

    if cmd == 'auto':
        prompt_str = ' '.join(args.prompt).strip()
        explicit_lang = getattr(args, 'lang', None)
        lang = explicit_lang or nox_scaffold.detect_user_ui_language(args.symptom if args.target is not None else prompt_str, default='pt-BR')
        technical = bool(getattr(args, 'technical', False))
        parsed = nox_issues.parse_natural_language_request(prompt_str) if prompt_str else {'intent': 'create'}
        if args.target is not None:
            res = nox_scaffold.auto_fix_extension(
                args.target,
                args.symptom,
                ecosystem=args.ecosystem,
                ui_lang=explicit_lang,
                build_task=args.build_task,
                technical=technical,
                site_url=args.site_url,
                allow_local_fixture=bool(args.allow_local_fixture),
            )
        elif parsed.get('intent') == 'fix' and not args.site_url and not prompt_str.startswith('http'):
            res = {
                **nox_core.format_adaptive_response(
                    {
                        'status': 'INCONCLUSIVE',
                        'action': 'auto',
                        'ui_lang': lang,
                        'ecosystem': args.ecosystem or parsed.get('inferred_ecosystem'),
                        'user_message': (
                            'To automatically diagnose and fix a broken extension, tell me its folder or file (--target).'
                            if lang == 'en'
                            else 'Para diagnosticar e corrigir uma extensão quebrada automaticamente, informe a pasta ou arquivo dela (--target).'
                        ),
                        'next_step': (
                            'Send the extension name/folder or describe what stops working (search, chapters, or images).'
                            if lang == 'en'
                            else 'Envie a pasta/arquivo da extensão ou descreva o problema (busca, capítulos ou imagens).'
                        ),
                        'parsed_request': parsed,
                    },
                    technical=technical,
                    lang=lang,
                )
            }
        else:
            res = nox_scaffold.auto_create_extension(
                prompt_str or 'Create extension',
                name=args.name,
                ecosystem=args.ecosystem,
                ui_lang=explicit_lang,
                output_dir=args.output,
                repo_root=args.repo,
                build_task=args.build_task,
                dry_run=bool(getattr(args, 'dry_run', False)),
                technical=technical,
                site_url=args.site_url,
                allow_local_fixture=bool(args.allow_local_fixture),
            )
        _emit(res, as_json=args.json, beginner=args.beginner, lang=res.get('ui_lang', lang))
        return _exit_code_for_status(res['status'])

    if cmd == 'auto-create':
        explicit_lang = getattr(args, 'lang', None)
        technical = bool(getattr(args, 'technical', False))
        res = nox_scaffold.auto_create_extension(
            ' '.join(args.prompt),
            name=args.name,
            ecosystem=args.ecosystem,
            source_lang=args.source_lang,
            ui_lang=explicit_lang,
            output_dir=args.output,
            repo_root=args.repo,
            build_task=args.build_task,
            dry_run=bool(getattr(args, 'dry_run', False)),
            technical=technical,
            site_url=args.site_url,
            allow_local_fixture=bool(args.allow_local_fixture),
        )
        _emit(res, as_json=args.json, beginner=args.beginner, lang=res.get('ui_lang', 'pt-BR'))
        return _exit_code_for_status(res['status'])

    if cmd == 'auto-fix':
        explicit_lang = getattr(args, 'lang', None)
        technical = bool(getattr(args, 'technical', False))
        attempts: list[dict[str, Any]] = []
        if args.attempts_json and args.attempts_json.is_file():
            loaded = json.loads(args.attempts_json.read_text(encoding='utf-8'))
            if isinstance(loaded, list):
                attempts = [x for x in loaded if isinstance(x, dict)]
        res = nox_scaffold.auto_fix_extension(
            args.target,
            args.symptom,
            ecosystem=args.ecosystem,
            ui_lang=explicit_lang,
            attempts=attempts,
            build_task=args.build_task,
            technical=technical,
            site_url=args.site_url,
            allow_local_fixture=bool(args.allow_local_fixture),
        )
        _emit(res, as_json=args.json, beginner=args.beginner, lang=res.get('ui_lang', 'pt-BR'))
        return _exit_code_for_status(res['status'])

    if cmd == 'apk-deliver':
        lang = getattr(args, 'lang', 'pt-BR')
        technical = bool(getattr(args, 'technical', False))
        raw_res = nox_android.handle_apk_delivery_choice(
            args.apk,
            args.choice,
            destination=args.dest,
            overwrite=bool(args.overwrite),
            serial=args.serial,
            authorize_install=bool(args.authorize_install),
            expected_package=args.expected_package,
            lang=lang,
        )
        res = nox_core.format_adaptive_response(raw_res, technical=technical, lang=lang)
        _emit(res, as_json=args.json, beginner=args.beginner, lang=lang)
        return _exit_code_for_status(res['status'])

    if cmd == 'bisect':
        parts = shlex.split(args.test_cmd)
        sandbox_blocked: dict[str, Any] = {}

        def _sandboxed_bisect_check(wt: Path) -> bool:
            sb = nox_android.run_in_bwrap_sandbox(wt, parts, timeout=60)
            if sb['status'] == 'BLOCKED' or sb.get('returncode') is None:
                sandbox_blocked['result'] = {
                    'status': 'BLOCKED',
                    'reason': sb.get('reason', 'bwrap sandbox unavailable for bisect --test-cmd'),
                    'sandbox': sb.get('sandbox'),
                    'executed_unprotected': False,
                }
                raise RuntimeError('NOX_BISECT_SANDBOX_BLOCKED')
            return sb['returncode'] == 0

        try:
            res = nox_android.run_git_bisect_regression(
                args.repo,
                args.good,
                args.bad,
                _sandboxed_bisect_check,
            )
        except RuntimeError as exc:
            if str(exc) != 'NOX_BISECT_SANDBOX_BLOCKED' or 'result' not in sandbox_blocked:
                raise
            res = sandbox_blocked['result']
        _emit(res, as_json=args.json, beginner=args.beginner, lang=args.lang)
        return _exit_code_for_status(res['status'])

    return 1


if __name__ == '__main__':
    raise SystemExit(main())
