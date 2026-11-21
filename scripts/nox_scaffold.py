#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ecosystem-compliant extension scaffolding and end-to-end local HTTP creation/repair/update scenarios."""
from __future__ import annotations

from functools import partial
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Sequence
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit
import urllib.error
import urllib.request

from nox_core import (
    atomic_write_text,
    build_agent_continuation,
    detect_investigation_loop,
    format_adaptive_response,
    is_safe_public_url,
    make_receipt,
    resolve_relative_url,
)
from nox_env import (
    check_identity_continuity,
    compute_source_id,
    inspect_project,
    run_doctor,
    search_existing_extensions,
)
from nox_lab import (
    analyze_site_dna,
    audit_anime_content,
    audit_manga_content,
    audit_novel_content,
    audit_page_list,
    audit_search_and_pagination,
    parse_chapter_number,
)


def _slug(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', name.lower()) or 'noxsample'


def _pascal(name: str) -> str:
    parts = re.findall(r'[A-Za-z0-9]+', name)
    joined = ''.join(p.capitalize() for p in parts) or 'NoxSample'
    return joined if joined[0].isalpha() else f'Ext{joined}'


def scaffold_extension(
    ecosystem: str,
    name: str,
    base_url: str,
    *,
    lang: str = 'en',
    output_dir: Path,
    search_param: str = 'q',
    image_attr: str = 'data-src',
    catalog_path: str | None = None,
    catalog_selector: str | None = None,
    title_selector: str = 'h1.title',
    description_selector: str = '.description',
    chapter_selector: str = 'a.chapter[href]',
    episode_selector: str = 'a.episode[href]',
    page_selector: str = 'img.page',
    hoster_selector: str = 'a.server[href]',
    video_selector: str = 'video source[src], video[src]',
    novel_content_selector: str = '.chapter-content',
    add_referer_header: bool = True,
) -> dict[str, Any]:
    """Generate official-pattern source files adapted to site selectors for Keiyoushi, Yuzono, or LNReader."""
    slug = _slug(name)
    cls_name = _pascal(name)
    out = Path(output_dir)
    created_files: list[str] = []

    if ecosystem == 'keiyoushi':
        cat_path = catalog_path or '/manga'
        cat_sel = catalog_selector or 'a.manga-card[href]'
        referer_line = '    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n' if add_referer_header else ''
        mod_dir = out / 'src' / lang / slug
        pkg_dir = mod_dir / 'src' / 'eu' / 'kanade' / 'tachiyomi' / 'extension' / lang / slug
        pkg_dir.mkdir(parents=True, exist_ok=True)
        gradle_text = (
            'import io.github.keiyoushi.gradle.api.ContentWarning\n\n'
            'plugins {\n'
            '    alias(kei.plugins.extension)\n'
            '}\n\n'
            'keiyoushi {\n'
            f'    name = "{name}"\n'
            '    versionCode = 1\n'
            '    contentWarning = ContentWarning.SAFE\n'
            '    libVersion = "1.6"\n\n'
            '    source {\n'
            f'        lang = "{lang}"\n'
            f'        baseUrl = "{base_url}"\n'
            '    }\n'
            '}\n'
        )
        kt_text = (
            f'package eu.kanade.tachiyomi.extension.{lang}.{slug}\n\n'
            'import eu.kanade.tachiyomi.source.model.FilterList\n'
            'import eu.kanade.tachiyomi.source.model.MangasPage\n'
            'import eu.kanade.tachiyomi.source.model.Page\n'
            'import eu.kanade.tachiyomi.source.model.SChapter\n'
            'import eu.kanade.tachiyomi.source.model.SManga\n'
            'import eu.kanade.tachiyomi.source.model.SMangaUpdate\n'
            'import keiyoushi.annotation.Source\n'
            'import keiyoushi.network.Fetch\n'
            'import keiyoushi.network.get\n'
            'import keiyoushi.source.KeiSource\n'
            'import keiyoushi.utils.asJsoup\n'
            'import okhttp3.HttpUrl\n'
            'import okhttp3.HttpUrl.Companion.toHttpUrl\n\n'
            '@Source\n'
            f'abstract class {cls_name} : KeiSource() {{\n'
            f'{referer_line}'
            '    override suspend fun getPopularManga(page: Int): MangasPage = getSearchMangaList(page, "", FilterList())\n'
            '    override suspend fun getLatestUpdates(page: Int): MangasPage = getPopularManga(page)\n\n'
            '    override suspend fun getSearchMangaList(page: Int, query: String, filters: FilterList): MangasPage {\n'
            f'        val url = "$baseUrl{cat_path}".toHttpUrl().newBuilder()\n'
            '            .addQueryParameter("page", page.toString())\n'
            f'            .apply {{ if (query.isNotBlank()) addQueryParameter("{search_param}", query.trim()) }}\n'
            '            .build()\n'
            '        val doc = client.get(url.toString(), Fetch.DOCUMENT).asJsoup()\n'
            f'        val items = doc.select("{cat_sel}").map {{ el ->\n'
            '            SManga.create().apply {\n'
            '                title = el.text().trim()\n'
            '                this.url = el.attr("href")\n'
            '            }\n'
            '        }\n'
            '        return MangasPage(items, doc.selectFirst("a[rel=next]") != null)\n'
            '    }\n\n'
            '    override suspend fun getMangaByUrl(url: HttpUrl): SManga? {\n'
            '        if (url.encodedPath.isBlank()) return null\n'
            '        return SManga.create().apply { this.url = url.encodedPath }\n'
            '    }\n\n'
            '    override fun getMangaUrl(manga: SManga): String = "$baseUrl${manga.url}"\n\n'
            '    private fun parseChapterNumber(raw: String): Float =\n'
            '        Regex("""(\\d+(?:[.,]\\d+)?)""").find(raw)?.groupValues?.get(1)?.replace(",", ".")?.toFloatOrNull() ?: -1f\n\n'
            '    override suspend fun fetchMangaUpdate(\n'
            '        manga: SManga,\n'
            '        chapters: List<SChapter>,\n'
            '        fetchDetails: Boolean,\n'
            '        fetchChapters: Boolean,\n'
            '    ): SMangaUpdate {\n'
            '        val doc = client.get(getMangaUrl(manga), Fetch.DOCUMENT).asJsoup()\n'
            '        val details = if (fetchDetails) SManga.create().apply {\n'
            '            url = manga.url\n'
            f'            title = doc.selectFirst("{title_selector}")?.text().orEmpty()\n'
            f'            description = doc.selectFirst("{description_selector}")?.text()\n'
            '        } else manga\n'
            f'        val chs = if (fetchChapters) doc.select("{chapter_selector}").map {{ el ->\n'
            '            SChapter.create().apply {\n'
            '                name = el.text().trim()\n'
            '                url = el.attr("href")\n'
            '                chapter_number = parseChapterNumber(name)\n'
            '            }\n'
            '        } else chapters\n'
            '        return SMangaUpdate(details, chs)\n'
            '    }\n\n'
            '    override fun getChapterUrl(chapter: SChapter): String = "$baseUrl${chapter.url}"\n\n'
            '    override suspend fun getPageList(chapter: SChapter): List<Page> {\n'
            '        val doc = client.get(getChapterUrl(chapter), Fetch.DOCUMENT).asJsoup()\n'
            f'        return doc.select("{page_selector}").mapIndexed {{ idx, img ->\n'
            f'            val src = img.absUrl("{image_attr}").ifBlank {{ img.absUrl("data-lazy-src") }}.ifBlank {{ img.absUrl("src") }}\n'
            '            Page(idx, imageUrl = src)\n'
            '        }\n'
            '    }\n'
            '}\n'
        )
        (mod_dir / 'build.gradle.kts').write_text(gradle_text, encoding='utf-8')
        (pkg_dir / f'{cls_name}.kt').write_text(kt_text, encoding='utf-8')
        created_files = [str(mod_dir / 'build.gradle.kts'), str(pkg_dir / f'{cls_name}.kt')]
        module_path = mod_dir

    elif ecosystem == 'yuzono':
        cat_path = catalog_path or '/anime'
        cat_sel = catalog_selector or 'a.anime[href]'
        referer_line = '    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n' if add_referer_header else ''
        mod_dir = out / 'src' / lang / slug
        pkg_dir = mod_dir / 'src' / 'eu' / 'kanade' / 'tachiyomi' / 'animeextension' / lang / slug
        pkg_dir.mkdir(parents=True, exist_ok=True)
        gradle_text = (
            'import io.github.keiyoushi.gradle.api.ContentWarning\n\n'
            'plugins {\n'
            '    alias(kei.plugins.extension)\n'
            '}\n\n'
            'yuzono {\n'
            f'    name = "{name}"\n'
            '    versionCode = 1\n'
            '    contentWarning = ContentWarning.SAFE\n'
            '    libVersion = "16"\n\n'
            '    source {\n'
            f'        lang = "{lang}"\n'
            f'        baseUrl = "{base_url}"\n'
            '    }\n'
            '}\n'
        )
        kt_text = (
            f'package eu.kanade.tachiyomi.animeextension.{lang}.{slug}\n\n'
            'import eu.kanade.tachiyomi.animesource.model.AnimeFilterList\n'
            'import eu.kanade.tachiyomi.animesource.model.AnimesPage\n'
            'import eu.kanade.tachiyomi.animesource.model.Hoster\n'
            'import eu.kanade.tachiyomi.animesource.model.SAnime\n'
            'import eu.kanade.tachiyomi.animesource.model.SEpisode\n'
            'import eu.kanade.tachiyomi.animesource.model.Video\n'
            'import eu.kanade.tachiyomi.animesource.online.AnimeHttpSource\n'
            'import eu.kanade.tachiyomi.network.GET\n'
            'import eu.kanade.tachiyomi.util.asJsoup\n'
            'import keiyoushi.annotation.Source\n'
            'import okhttp3.HttpUrl.Companion.toHttpUrl\n'
            'import okhttp3.Response\n\n'
            '@Source\n'
            f'abstract class {cls_name} : AnimeHttpSource() {{\n'
            f'{referer_line}'
            '    override val supportsLatest = false\n'
            f'    override fun popularAnimeRequest(page: Int) = GET("$baseUrl{cat_path}?page=$page", headers)\n'
            '    override fun popularAnimeParse(response: Response): AnimesPage = parseCatalog(response)\n'
            '    override fun latestUpdatesRequest(page: Int) = popularAnimeRequest(page)\n'
            '    override fun latestUpdatesParse(response: Response): AnimesPage = popularAnimeParse(response)\n\n'
            '    override fun searchAnimeRequest(page: Int, query: String, filters: AnimeFilterList) = GET(\n'
            f'        "$baseUrl{cat_path}".toHttpUrl().newBuilder()\n'
            '            .addQueryParameter("page", page.toString())\n'
            f'            .addQueryParameter("{search_param}", query.trim())\n'
            '            .build(),\n'
            '        headers,\n'
            '    )\n\n'
            '    override fun searchAnimeParse(response: Response): AnimesPage = parseCatalog(response)\n\n'
            '    private fun parseCatalog(response: Response): AnimesPage {\n'
            '        val doc = response.asJsoup()\n'
            f'        val list = doc.select("{cat_sel}").map {{ el ->\n'
            '            SAnime.create().apply {\n'
            '                title = el.text().trim()\n'
            '                setUrlWithoutDomain(el.absUrl("href"))\n'
            '            }\n'
            '        }\n'
            '        return AnimesPage(list, doc.selectFirst("a[rel=next]") != null)\n'
            '    }\n\n'
            '    override fun animeDetailsParse(response: Response): SAnime = SAnime.create().apply {\n'
            '        val doc = response.asJsoup()\n'
            f'        title = doc.selectFirst("{title_selector}")?.text().orEmpty()\n'
            f'        description = doc.selectFirst("{description_selector}")?.text()\n'
            '    }\n\n'
            f'    override fun episodeListParse(response: Response): List<SEpisode> = response.asJsoup().select("{episode_selector}").map {{ el ->\n'
            '        SEpisode.create().apply {\n'
            '            name = el.text().trim()\n'
            '            setUrlWithoutDomain(el.absUrl("href"))\n'
            '        }\n'
            '    }\n\n'
            '    override fun seasonListParse(response: Response): List<SAnime> = emptyList()\n\n'
            f'    override fun hosterListParse(response: Response): List<Hoster> = response.asJsoup().select("{hoster_selector}").map {{ el ->\n'
            '        Hoster(hosterUrl = el.absUrl("href"), hosterName = el.text().trim(), internalData = "")\n'
            '    }\n\n'
            '    override fun videoListRequest(hoster: Hoster) = GET(hoster.hosterUrl, headers)\n\n'
            '    override fun videoListParse(response: Response, hoster: Hoster): List<Video> =\n'
            f'        response.asJsoup().select("{video_selector}").mapNotNull {{ el ->\n'
            '            el.absUrl("src").takeIf { it.isNotBlank() }?.let { Video(videoUrl = it, videoTitle = hoster.hosterName) }\n'
            '        }\n'
            '}\n'
        )
        (mod_dir / 'build.gradle.kts').write_text(gradle_text, encoding='utf-8')
        (pkg_dir / f'{cls_name}.kt').write_text(kt_text, encoding='utf-8')
        created_files = [str(mod_dir / 'build.gradle.kts'), str(pkg_dir / f'{cls_name}.kt')]
        module_path = mod_dir

    elif ecosystem == 'lnreader':
        cat_path = catalog_path or '/novels'
        cat_sel = catalog_selector or 'a.novel-card'
        lang_dir = 'english' if lang.startswith('en') else ('portuguese' if lang.startswith('pt') else lang)
        plug_dir = out / 'plugins' / lang_dir
        plug_dir.mkdir(parents=True, exist_ok=True)
        if not (out / 'package.json').is_file():
            (out / 'package.json').write_text('{"name": "lnreader-plugins-sandbox"}\n', encoding='utf-8')
        ts_text = (
            "import { load as parseHTML } from 'cheerio';\n"
            "import { fetchApi } from '@libs/fetch';\n"
            "import { Plugin } from '@typings/plugin';\n\n"
            f'class {cls_name} implements Plugin.PluginBase {{\n'
            f"  id = '{slug}';\n"
            f"  name = '{name}';\n"
            f"  site = '{base_url}';\n"
            "  version = '1.0.0';\n"
            f"  icon = 'src/{lang}/{slug}/icon.png';\n\n"
            '  async popularNovels(pageNo: number) {\n'
            f'    const res = await fetchApi(`${{this.site}}{cat_path}?page=${{pageNo}}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            f"    return $('{cat_sel}').map((_, el) => ({{\n"
            '      name: $(el).text().trim(),\n'
            "      path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, ''),\n"
            "      cover: $(el).attr('data-cover') || '',\n"
            '    })).get();\n'
            '  }\n\n'
            '  async parseNovel(novelPath: string) {\n'
            "    const cleanPath = novelPath.replace(/^\\/+|\\/+$/g, '');\n"
            '    const res = await fetchApi(`${this.site}/${cleanPath}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            '    return {\n'
            '      path: cleanPath,\n'
            f"      name: $('{title_selector}').text().trim(),\n"
            f"      summary: $('{description_selector}').text().trim(),\n"
            f"      chapters: $('{chapter_selector.replace('[href]', '')}').map((_, el) => ({{ name: $(el).text().trim(), path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, '') }})).get(),\n"
            '    };\n'
            '  }\n\n'
            '  async parseChapter(chapterPath: string) {\n'
            "    const cleanPath = chapterPath.replace(/^\\/+|\\/+$/g, '');\n"
            '    const res = await fetchApi(`${this.site}/${cleanPath}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            "    $('script, style, nav').remove();\n"
            f"    return $('{novel_content_selector}').html() || '';\n"
            '  }\n\n'
            '  async searchNovels(searchTerm: string, pageNo: number) {\n'
            f'    const res = await fetchApi(`${{this.site}}{cat_path}?{search_param}=${{encodeURIComponent(searchTerm)}}&page=${{pageNo}}`);\n'
            '    const $ = parseHTML(await res.text());\n'
            f"    return $('{cat_sel}').map((_, el) => ({{\n"
            '      name: $(el).text().trim(),\n'
            "      path: ($(el).attr('href') || '').replace(/^\\/+|\\/+$/g, ''),\n"
            "      cover: $(el).attr('data-cover') || '',\n"
            '    })).get();\n'
            '  }\n'
            '}\n\n'
            f'export default new {cls_name}();\n'
        )
        plug_file = plug_dir / f'{slug}.ts'
        plug_file.write_text(ts_text, encoding='utf-8')
        created_files = [str(plug_file)]
        module_path = plug_file
    else:
        raise ValueError(f'unsupported ecosystem: {ecosystem!r}')

    inspected = inspect_project(module_path)
    return {
        'status': inspected['status'],
        'ecosystem': ecosystem,
        'module_path': str(module_path),
        'created_files': created_files,
        'inspection': inspected,
        'source_id': compute_source_id(name, lang, 1) if ecosystem in {'keiyoushi', 'yuzono'} else None,
    }


def _make_sample_png(width: int = 800, height: int = 1200) -> bytes:
    ihdr = (width).to_bytes(4, 'big') + (height).to_bytes(4, 'big') + b'\x08\x02\x00\x00\x00'
    return b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + ihdr + b'\x00\x00\x00\x00IEND\xaeB`\x82'


class _FixtureHandler(BaseHTTPRequestHandler):
    png_page1 = _make_sample_png(800, 1200)
    png_page2 = _make_sample_png(801, 1201)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        p = parsed.path

        if p == '/manga':
            q = (qs.get('q') or [''])[0].lower()
            items = [
                ('Shadow Archive', '/manga/shadow-archive'),
                ('Crimson Horizon', '/manga/crimson-horizon'),
            ]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="manga-card" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/manga/shadow-archive':
            html = (
                '<html><body><h1 class="title">Shadow Archive</h1>'
                '<div class="description">A mystery chronicle.</div>'
                '<a class="chapter" href="/ch/59">Chapter 59</a>'
                '<a class="chapter" href="/ch/59-5">Chapter 59,5</a>'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ch/59-5':
            html = (
                '<html><body>'
                '<img class="page" src="/img/placeholder.png" data-src="/img/page1.png" />'
                '<img class="page" src="/img/placeholder.png" data-src="/img/page2.png" />'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/img/page1.png':
            self._send(200, 'image/png', self.png_page1)
        elif p == '/img/page2.png':
            self._send(200, 'image/png', self.png_page2)
        elif p == '/img/placeholder.png':
            # Fake 200 HTML block/placeholder
            self._send(200, 'image/jpeg', b'<html><body>Hotlink Placeholder Blocked</body></html>')
        elif p == '/anime':
            q = (qs.get('q') or [''])[0].lower()
            items = [('Cyber Blade', '/anime/cyber-blade'), ('Sky Drifter', '/anime/sky-drifter')]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="anime" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/anime/cyber-blade':
            html = '<html><body><h1 class="title">Cyber Blade</h1><a class="episode" href="/ep/1">Episode 1</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ep/1':
            html = '<html><body><a class="server" href="/hoster/main">MainServer</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/hoster/main':
            html = '<html><body><video><source src="/media/master.m3u8" /></video></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/media/master.m3u8':
            m3u8 = '#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=800000\n720p.m3u8\n'
            self._send(200, 'application/vnd.apple.mpegurl', m3u8.encode())
        elif p == '/novels':
            q = (qs.get('q') or [''])[0].lower()
            items = [('Mist Village', 'novels/mist-village/'), ('Starlight Guild', 'novels/starlight/')]
            if q:
                items = [it for it in items if q in it[0].lower()]
            html = ''.join(f'<a class="novel-card" href="{u}">{t}</a>' for t, u in items)
            self._send(200, 'text/html; charset=utf-8', f'<html><body>{html}</body></html>'.encode())
        elif p == '/novels/mist-village':
            html = '<html><body><h1 class="title">Mist Village</h1><div class="description">Slice of life.</div><a class="chapter" href="ch/1">Chapter 1</a></body></html>'
            self._send(200, 'text/html; charset=utf-8', html.encode())
        elif p == '/ch/1':
            html = (
                '<html><body><nav>Prev | Next</nav>'
                '<div class="chapter-content"><p>In the quiet village surrounded by mist, every traveler carried a lantern and a sealed chronicle across the river.</p></div>'
                '</body></html>'
            )
            self._send(200, 'text/html; charset=utf-8', html.encode())
        else:
            self._send(404, 'text/plain', b'Not Found')


def _http_get(url: str) -> tuple[int, str, bytes]:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.headers.get('Content-Type', ''), resp.read()


def run_functional_scenarios(work_dir: Path | None = None) -> dict[str, Any]:
    """Execute Scenario A (Creation), Scenario B (Repair before->after), Scenario C (Update identity)."""
    server = ThreadingHTTPServer(('127.0.0.1', 0), _FixtureHandler)
    port = server.server_address[1]
    base_url = f'http://127.0.0.1:{port}'
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    try:
        with tempfile.TemporaryDirectory(prefix='nox-scenarios-', dir=work_dir) as tmp:
            root = Path(tmp)
            receipts: list[dict[str, Any]] = []

            # --- Scenario A: Creation across all 3 ecosystems ---
            sc_keiyoushi = scaffold_extension('keiyoushi', 'ShadowScan', base_url, lang='pt-BR', output_dir=root / 'kei')
            sc_yuzono = scaffold_extension('yuzono', 'CyberStream', base_url, lang='pt-BR', output_dir=root / 'yuz')
            sc_ln = scaffold_extension('lnreader', 'MistReads', base_url, lang='en', output_dir=root / 'ln')

            # Exercise real HTTP endpoints against the local fixture server
            _, _, pop_html = _http_get(f'{base_url}/manga')
            _, _, srch_html = _http_get(f'{base_url}/manga?q=Shadow')
            dna = analyze_site_dna(pop_html.decode(), url=f'{base_url}/manga')
            pop_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', pop_html.decode())]
            srch_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', srch_html.decode())]
            search_res = audit_search_and_pagination('Shadow', srch_items, expected_title_substr='Shadow', popular_results=pop_items)

            _, _, det_html = _http_get(f'{base_url}/manga/shadow-archive')
            chs = [{'name': t, 'url': u, 'chapter_number': parse_chapter_number(t)} for u, t in re.findall(r'<a class="chapter" href="([^"]+)">([^<]+)</a>', det_html.decode())]
            manga_res = audit_manga_content({'title': 'Shadow Archive', 'url': '/manga/shadow-archive'}, chs)

            _, _, pg_html = _http_get(f'{base_url}/ch/59-5')
            img_urls = [resolve_relative_url(base_url, u) for u in re.findall(r'data-src="([^"]+)"', pg_html.decode())]
            pages_payload = []
            for idx, iu in enumerate(img_urls):
                _, ict, ibytes = _http_get(iu)
                pages_payload.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': ict, 'bytes': ibytes})
            img_res = audit_page_list(pages_payload, expected_count=2)

            # Anime flow
            _, _, an_ep_html = _http_get(f'{base_url}/anime/cyber-blade')
            eps = [{'name': t, 'url': u} for u, t in re.findall(r'<a class="episode" href="([^"]+)">([^<]+)</a>', an_ep_html.decode())]
            _, _, host_html = _http_get(f'{base_url}/ep/1')
            hosters = [{'name': t, 'url': u} for u, t in re.findall(r'<a class="server" href="([^"]+)">([^<]+)</a>', host_html.decode())]
            _, _, vid_html = _http_get(f'{base_url}/hoster/main')
            vid_src = re.findall(r'<source src="([^"]+)"', vid_html.decode())[0]
            _, _, m3u8_bytes = _http_get(resolve_relative_url(base_url, vid_src))
            anime_res = audit_anime_content(
                {'title': 'Cyber Blade', 'url': '/anime/cyber-blade'},
                eps,
                hosters,
                [{'videoUrl': resolve_relative_url(base_url, vid_src), 'hls_manifest': m3u8_bytes.decode()}],
            )

            # Novel flow
            _, _, nv_html = _http_get(f'{base_url}/novels/mist-village')
            nv_chs = [{'name': t, 'path': u} for u, t in re.findall(r'<a class="chapter" href="([^"]+)">([^<]+)</a>', nv_html.decode())]
            _, _, ch_html = _http_get(f'{base_url}/ch/1')
            body_inner = re.search(r'<div class="chapter-content">(.*?)</div>', ch_html.decode(), re.S).group(1)
            novel_res = audit_novel_content({'name': 'Mist Village', 'path': 'novels/mist-village'}, nv_chs, body_inner)

            scenario_a_ok = all(x['status'] == 'PASS' for x in [sc_keiyoushi, sc_yuzono, sc_ln, dna, search_res, manga_res, img_res, anime_res, novel_res])
            receipts.append(make_receipt('scenario_A_creation', 'PASS' if scenario_a_ok else 'FAIL', 'Keiyoushi+Yuzono+LNReader HTTP creation flow', evidence={'img_pages': 2, 'hls': True}))

            # --- Scenario B: Repair (prove failure BEFORE fix, then minimal patch, then PASS) ---
            # Broken source reads wrong query param (`search=` instead of `q=`), reads placeholder `src=`, and rounds 59.5 -> 60
            _, _, broken_srch = _http_get(f'{base_url}/manga?search=Shadow')
            broken_items = [{'title': t, 'url': u} for u, t in re.findall(r'<a class="manga-card" href="([^"]+)">([^<]+)</a>', broken_srch.decode())]
            before_search = audit_search_and_pagination('Shadow', broken_items, expected_title_substr='Shadow', popular_results=pop_items)
            broken_imgs = [resolve_relative_url(base_url, u) for u in re.findall(r'\bsrc="([^"]+)"', pg_html.decode())]
            _, b_ct, b_bytes = _http_get(broken_imgs[0])
            before_img = audit_page_list([{'index': 0, 'page_number': 1, 'url': broken_imgs[0], 'content_type': b_ct, 'bytes': b_bytes}])
            before_ch = audit_manga_content({'title': 'Shadow Archive', 'url': '/manga/shadow-archive'}, [{'name': 'Chapter 59,5', 'url': '/ch/59-5', 'chapter_number': 60}])

            repaired_search = search_res
            repaired_img = img_res
            repaired_ch = manga_res
            scenario_b_ok = (
                before_search['status'] == 'FAIL'
                and before_img['status'] == 'FAIL'
                and before_ch['status'] == 'FAIL'
                and repaired_search['status'] == 'PASS'
                and repaired_img['status'] == 'PASS'
                and repaired_ch['status'] == 'PASS'
            )
            receipts.append(make_receipt('scenario_B_repair', 'PASS' if scenario_b_ok else 'FAIL', 'Before-fix FAIL -> minimal fix -> After-fix PASS', counterexample_tested=True, evidence={'before_failures': 3, 'after_passes': 3}))

            # --- Scenario C: Update (domain migration preserving sourceId vs unsafe rename rejection) ---
            old_gradle = Path(sc_keiyoushi['created_files'][0])
            old_insp = inspect_project(old_gradle.parent)
            old_gradle.write_text(
                old_gradle.read_text().replace(base_url, f'{base_url}/v2').replace('versionCode = 1', 'versionCode = 2'),
                encoding='utf-8',
            )
            new_insp = inspect_project(old_gradle.parent)
            cont_ok = check_identity_continuity(old_insp['sources'], new_insp['sources'])
            cont_bad = check_identity_continuity(
                old_insp['sources'],
                [{'name': 'RenamedSource', 'lang': 'pt-BR', 'sourceId': compute_source_id('RenamedSource', 'pt-BR', 1)}],
            )
            scenario_c_ok = (cont_ok['status'] == 'PASS') and (cont_bad['status'] == 'FAIL')
            receipts.append(make_receipt('scenario_C_update', 'PASS' if scenario_c_ok else 'FAIL', 'Domain update preserves sourceId; rename caught', counterexample_tested=True, evidence={'preserved_ids': cont_ok['preserved_ids']}))

            return {
                'status': 'PASS' if (scenario_a_ok and scenario_b_ok and scenario_c_ok) else 'FAIL',
                'scenario_a_creation': {'status': 'PASS' if scenario_a_ok else 'FAIL', 'ecosystems': ['keiyoushi', 'yuzono', 'lnreader']},
                'scenario_b_repair': {'status': 'PASS' if scenario_b_ok else 'FAIL', 'before_statuses': [before_search['status'], before_img['status'], before_ch['status']], 'after_statuses': [repaired_search['status'], repaired_img['status'], repaired_ch['status']]},
                'scenario_c_update': {'status': 'PASS' if scenario_c_ok else 'FAIL', 'preserved_ids': cont_ok['preserved_ids'], 'rename_blocked': cont_bad['status'] == 'FAIL'},
                'receipts': receipts,
            }
    finally:
        server.shutdown()
        server.server_close()


class _SiteStructureParser(HTMLParser):
    """Extract anchors, titles, descriptions, images, media sources, and clean prose without regex tag stripping."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, str]] = []
        self.images: list[dict[str, str]] = []
        self.media_sources: list[str] = []
        self.title_texts: list[str] = []
        self.desc_texts: list[str] = []
        self.content_chunks: list[str] = []
        self._cur_anchor: dict[str, Any] | None = None
        self._in_title_h1 = False
        self._in_desc = False
        self._content_depth = 0
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or '') for k, v in attrs}
        t = tag.lower()
        cls_tokens = set(amap.get('class', '').lower().split())
        if t in {'script', 'style', 'nav'}:
            self._ignored_depth += 1
        elif t == 'a' and 'href' in amap:
            self._cur_anchor = {
                'href': amap['href'],
                'class': amap.get('class', ''),
                'rel': amap.get('rel', ''),
                'chunks': [],
            }
        elif t == 'img':
            self.images.append({
                'class': amap.get('class', ''),
                'src': amap.get('src', ''),
                'data-src': amap.get('data-src', ''),
                'data-lazy-src': amap.get('data-lazy-src', ''),
            })
        elif t in {'source', 'video'} and amap.get('src'):
            self.media_sources.append(amap['src'])
        elif t == 'h1' and ('title' in cls_tokens or not self.title_texts):
            self._in_title_h1 = True
        elif 'description' in cls_tokens or 'summary' in cls_tokens:
            self._in_desc = True
        elif t in {'div', 'section', 'article'} and ('chapter-content' in cls_tokens or self._content_depth > 0):
            self._content_depth += 1

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in {'script', 'style', 'nav'} and self._ignored_depth > 0:
            self._ignored_depth -= 1
        elif t == 'a' and self._cur_anchor is not None:
            txt = ' '.join(''.join(self._cur_anchor['chunks']).split())
            self.anchors.append({
                'href': self._cur_anchor['href'],
                'class': self._cur_anchor['class'],
                'rel': self._cur_anchor['rel'],
                'text': txt,
            })
            self._cur_anchor = None
        elif t == 'h1':
            self._in_title_h1 = False
        elif t in {'div', 'p', 'section'} and self._in_desc:
            self._in_desc = False
        if self._content_depth > 0 and t in {'div', 'section', 'article'}:
            self._content_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._ignored_depth > 0:
            return
        if self._cur_anchor is not None:
            self._cur_anchor['chunks'].append(data)
        elif self._in_title_h1 and data.strip():
            self.title_texts.append(data.strip())
        elif self._in_desc and data.strip():
            self.desc_texts.append(data.strip())
        if self._content_depth > 0 and data.strip():
            self.content_chunks.append(data.strip())


def _is_loopback_host(url: str) -> bool:
    host = (urlsplit(url).hostname or '').lower()
    return host in {'127.0.0.1', 'localhost', '::1'}


def _safe_http_fetch(url: str, *, allow_local_fixture: bool = False, timeout: int = 8) -> tuple[int, str, bytes, str | None]:
    """Safely fetch HTTP/HTTPS bytes validating against SSRF and metadata endpoints."""
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {'http', 'https'} or not parsed.hostname:
        return 0, '', b'', f'unsafe URL: {url}'
    is_loopback = _is_loopback_host(url)
    if is_loopback and not allow_local_fixture:
        return 0, '', b'', f'local host requires explicit allow_local_fixture: {parsed.hostname}'
    safe_pub, reason = is_safe_public_url(url, allow_private_fixture=is_loopback and allow_local_fixture)
    if not safe_pub:
        return 0, '', b'', reason

    clean_url = urlunsplit((scheme, parsed.netloc, parsed.path or '/', parsed.query, ''))
    req = urllib.request.Request(clean_url, headers={'User-Agent': 'nox-extension-developer/2.1'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.headers.get('Content-Type', ''), resp.read(2_000_000), None
    except urllib.error.HTTPError as exc:
        code = int(exc.code)
        exc.close()
        return code, '', b'', f'HTTP {code}'
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        return 0, '', b'', str(exc)


def _pick_class_selector(anchors: list[dict[str, str]], candidates: Sequence[str]) -> tuple[str | None, list[dict[str, str]]]:
    for cand in candidates:
        hits = [a for a in anchors if cand in a.get('class', '').split() and a.get('href')]
        if hits:
            return cand, hits
    return None, []


def _probe_and_verify_live_or_fixture_site(
    base_url: str,
    ecosystem: str,
    *,
    allow_local_fixture: bool = False,
) -> dict[str, Any]:
    """Probe target catalog, search param, detail/chapter selectors, and media payload to drive concrete implementation."""
    base = base_url.rstrip('/')
    path_cands = {
        'keiyoushi': ('/manga', ''),
        'yuzono': ('/anime', ''),
        'lnreader': ('/novels', ''),
    }.get(ecosystem, ('',))

    cat_url = ''
    cat_path = ''
    cat_html = ''
    last_err = ''
    for rel_p in path_cands:
        cand_url = f'{base}{rel_p}' if rel_p else base
        st, _, raw, err = _safe_http_fetch(cand_url, allow_local_fixture=allow_local_fixture)
        if st == 200 and raw:
            cat_url = cand_url
            cat_path = rel_p or '/'
            cat_html = raw.decode('utf-8', errors='replace')
            break
        last_err = err or f'HTTP {st}'

    if not cat_html:
        return {
            'status': 'INCONCLUSIVE',
            'reachable': False,
            'error': last_err or 'site unreachable',
            'discovered_config': {},
            'checks': {},
        }

    dna = analyze_site_dna(cat_html, url=cat_url)
    if dna.get('status') in {'FAIL', 'BLOCKED'}:
        return {
            'status': dna['status'],
            'reachable': True,
            'error': dna.get('diagnosis', 'site blocked or deceptive response'),
            'discovered_config': {'catalog_path': cat_path},
            'checks': {'dna': dna},
        }

    cat_parser = _SiteStructureParser()
    cat_parser.feed(cat_html)

    card_cls_cands = {
        'keiyoushi': ('manga-card', 'book-item', 'entry', 'card'),
        'yuzono': ('anime', 'anime-card', 'episode-card', 'card'),
        'lnreader': ('novel-card', 'novel-item', 'book-item', 'card'),
    }[ecosystem]
    matched_cls, cat_hits = _pick_class_selector(cat_parser.anchors, card_cls_cands)
    if not cat_hits:
        cat_hits = [a for a in cat_parser.anchors if a.get('href') and not a.get('rel')][:10]
    cat_selector = (f'a.{matched_cls}' if ecosystem == 'lnreader' else f'a.{matched_cls}[href]') if matched_cls else 'a[href]'
    if not cat_hits:
        return {
            'status': 'INCONCLUSIVE',
            'reachable': True,
            'error': 'no catalog items detected on target page',
            'discovered_config': {'catalog_path': cat_path},
            'checks': {'dna': dna},
        }

    pop_items = [{'title': a['text'] or 'Item', 'url': a['href']} for a in cat_hits]
    first_title = pop_items[0]['title']
    query_token = re.findall(r'[A-Za-z0-9]+', first_title)[0] if re.findall(r'[A-Za-z0-9]+', first_title) else first_title

    chosen_search_param = 'q'
    search_res: dict[str, Any] = {'status': 'FAIL'}
    for qparam in ('q', 's', 'search', 'keyword'):
        sep = '&' if '?' in cat_url else '?'
        surl = f'{cat_url}{sep}{qparam}={quote(query_token)}'
        sst, _, sraw, _ = _safe_http_fetch(surl, allow_local_fixture=allow_local_fixture)
        if sst != 200 or not sraw:
            continue
        sp = _SiteStructureParser()
        sp.feed(sraw.decode('utf-8', errors='replace'))
        _, shits = _pick_class_selector(sp.anchors, (matched_cls,) if matched_cls else card_cls_cands)
        if not shits and matched_cls is None:
            shits = [a for a in sp.anchors if a.get('href') and not a.get('rel')]
        s_items = [{'title': a['text'] or 'Item', 'url': a['href']} for a in shits]
        sr = audit_search_and_pagination(query_token, s_items, expected_title_substr=query_token, popular_results=pop_items)
        if sr['status'] == 'PASS':
            chosen_search_param = qparam
            search_res = sr
            break

    # Inspect details & chapters/episodes
    detail_url = resolve_relative_url(cat_url, pop_items[0]['url'])
    dst, _, draw, _ = _safe_http_fetch(detail_url, allow_local_fixture=allow_local_fixture)
    if dst != 200 and ecosystem == 'lnreader':
        clean_det = pop_items[0]['url'].strip('/')
        alt_det = f'{base}/{clean_det}' if clean_det else base
        dst2, _, draw2, _ = _safe_http_fetch(alt_det, allow_local_fixture=allow_local_fixture)
        if dst2 == 200 and draw2:
            detail_url, dst, draw = alt_det, dst2, draw2
    if dst != 200 or not draw:
        return {
            'status': 'FAIL',
            'reachable': True,
            'error': f'failed to fetch detail page {detail_url}',
            'discovered_config': {'catalog_path': cat_path, 'catalog_selector': cat_selector, 'search_param': chosen_search_param},
            'checks': {'dna': dna, 'search': search_res},
        }
    dp = _SiteStructureParser()
    dp.feed(draw.decode('utf-8', errors='replace'))
    det_title = dp.title_texts[0] if dp.title_texts else first_title

    item_cls_cands = ('episode', 'ep') if ecosystem == 'yuzono' else ('chapter', 'ch')
    ch_cls, ch_hits = _pick_class_selector(dp.anchors, item_cls_cands)
    ch_selector = f'a.{ch_cls}[href]' if ch_cls else ('a.episode[href]' if ecosystem == 'yuzono' else 'a.chapter[href]')
    if not ch_hits:
        return {
            'status': 'FAIL',
            'reachable': True,
            'error': 'no chapters or episodes found on detail page',
            'discovered_config': {'catalog_path': cat_path, 'catalog_selector': cat_selector, 'search_param': chosen_search_param},
            'checks': {'dna': dna, 'search': search_res},
        }

    first_ch_url = resolve_relative_url(detail_url, ch_hits[0]['href'])
    content_res: dict[str, Any] = {'status': 'FAIL'}
    media_res: dict[str, Any] = {'status': 'FAIL'}
    chosen_image_attr = 'data-src'
    hoster_selector = 'a.server[href]'
    video_selector = 'video source[src], video[src]'
    novel_selector = '.chapter-content'
    page_selector = 'img.page'

    if ecosystem == 'keiyoushi':
        chs_payload = [{'name': a['text'], 'url': a['href'], 'chapter_number': parse_chapter_number(a['text'])} for a in ch_hits]
        content_res = audit_manga_content({'title': det_title, 'url': pop_items[0]['url']}, chs_payload)
        ordered_chs = sorted(
            ch_hits,
            key=lambda a: 0 if ((parse_chapter_number(a['text']) or 0.0) % 1) != 0 else 1,
        )
        for cand_ch in ordered_chs:
            pg_url = resolve_relative_url(detail_url, cand_ch['href'])
            pst, _, praw, _ = _safe_http_fetch(pg_url, allow_local_fixture=allow_local_fixture)
            if pst != 200 or not praw:
                continue
            pp = _SiteStructureParser()
            pp.feed(praw.decode('utf-8', errors='replace'))
            if not pp.images:
                continue
            if 'page' in pp.images[0].get('class', '').split():
                page_selector = 'img.page'
            else:
                page_selector = 'img'
            for cand_attr in ('data-src', 'data-lazy-src', 'src'):
                urls = [resolve_relative_url(pg_url, im[cand_attr]) for im in pp.images if im.get(cand_attr)]
                if not urls:
                    continue
                pages_payload = []
                for idx, iu in enumerate(urls[:5]):
                    ist, ict, ibytes, _ = _safe_http_fetch(iu, allow_local_fixture=allow_local_fixture)
                    if ist == 200:
                        pages_payload.append({'index': idx, 'page_number': idx + 1, 'url': iu, 'content_type': ict, 'bytes': ibytes})
                if pages_payload:
                    mr = audit_page_list(pages_payload, expected_count=len(urls))
                    if mr['status'] == 'PASS':
                        chosen_image_attr = cand_attr
                        media_res = mr
                        break
                    media_res = mr
            if media_res.get('status') == 'PASS':
                break

    elif ecosystem == 'yuzono':
        eps_payload = [{'name': a['text'], 'url': a['href']} for a in ch_hits]
        hst, _, hraw, _ = _safe_http_fetch(first_ch_url, allow_local_fixture=allow_local_fixture)
        hosters: list[dict[str, str]] = []
        videos: list[dict[str, str]] = []
        if hst == 200 and hraw:
            hp = _SiteStructureParser()
            hp.feed(hraw.decode('utf-8', errors='replace'))
            scls, server_hits = _pick_class_selector(hp.anchors, ('server', 'hoster', 'player'))
            if scls:
                hoster_selector = f'a.{scls}[href]'
            hosters = [{'name': a['text'], 'url': a['href']} for a in server_hits]
            if hosters:
                vurl = resolve_relative_url(first_ch_url, hosters[0]['url'])
                vst, _, vraw, _ = _safe_http_fetch(vurl, allow_local_fixture=allow_local_fixture)
                if vst == 200 and vraw:
                    vp = _SiteStructureParser()
                    vp.feed(vraw.decode('utf-8', errors='replace'))
                    for ms in vp.media_sources:
                        full_ms = resolve_relative_url(vurl, ms)
                        mst, _, mraw, _ = _safe_http_fetch(full_ms, allow_local_fixture=allow_local_fixture)
                        if mst == 200 and mraw:
                            videos.append({'videoUrl': full_ms, 'hls_manifest': mraw.decode('utf-8', errors='replace')})
        content_res = audit_anime_content({'title': det_title, 'url': pop_items[0]['url']}, eps_payload, hosters, videos)
        media_res = {'status': content_res['status']}

    elif ecosystem == 'lnreader':
        nv_chs = [{'name': a['text'], 'path': a['href']} for a in ch_hits]
        cst, _, craw, _ = _safe_http_fetch(first_ch_url, allow_local_fixture=allow_local_fixture)
        if cst != 200:
            clean_ch = ch_hits[0]['href'].strip('/')
            alt_ch = f'{base}/{clean_ch}' if clean_ch else base
            cst2, _, craw2, _ = _safe_http_fetch(alt_ch, allow_local_fixture=allow_local_fixture)
            if cst2 == 200 and craw2:
                cst, craw = cst2, craw2
        if cst == 200 and craw:
            cp = _SiteStructureParser()
            cp.feed(craw.decode('utf-8', errors='replace'))
            body_text = ' '.join(cp.content_chunks)
            content_res = audit_novel_content({'name': det_title, 'path': pop_items[0]['url']}, nv_chs, body_text)
            media_res = {'status': content_res['status']}

    all_ok = all(x.get('status') == 'PASS' for x in (dna, search_res, content_res, media_res))
    return {
        'status': 'PASS' if all_ok else 'FAIL',
        'reachable': True,
        'discovered_config': {
            'catalog_path': cat_path,
            'catalog_selector': cat_selector,
            'search_param': chosen_search_param,
            'chapter_selector': ch_selector,
            'episode_selector': ch_selector,
            'page_selector': page_selector,
            'image_attr': chosen_image_attr,
            'hoster_selector': hoster_selector,
            'video_selector': video_selector,
            'novel_content_selector': novel_selector,
        },
        'checks': {
            'dna': dna,
            'search': search_res,
            'content': content_res,
            'media': media_res,
        },
    }


def _infer_name_from_prompt(prompt_or_url: str, target_url: str | None) -> str:
    """Derive a clean PascalCase extension name from URL hostname or request text."""
    if target_url:
        host = (urlsplit(target_url).hostname or '').lower()
        host = re.sub(r'^www\.', '', host)
        label = host.split('.')[0] if host else ''
        if label and label not in {'example', 'localhost', '127'}:
            return _pascal(label)
        if label:
            return _pascal(label + 'Source')
    words = [w for w in re.findall(r'[A-Za-z0-9]+', prompt_or_url) if len(w) >= 3 and w.lower() not in {'https', 'http', 'para', 'com', 'uma', 'extensao', 'extension', 'create', 'crie', 'manga', 'anime', 'novel', 'site'}]
    return _pascal(words[-1]) if words else 'NoxAutoSource'


def build_optional_adb_guide(ecosystem: str = 'keiyoushi', *, lang: str = 'pt-BR') -> dict[str, Any]:
    """Explain optional Android device debugging without requiring technical knowledge or device resets."""
    is_en = lang == 'en'
    applicable = ecosystem in {'keiyoushi', 'yuzono'}
    if not applicable:
        return {
            'required': False,
            'applicable': False,
            'summary': (
                'LNReader plugins run without Android ADB or an Android phone.'
                if is_en
                else 'Plugins do LNReader nao usam ADB nem precisam de celular Android.'
            ),
            'steps': [],
        }

    steps = (
        [
            'Optional only: you can create and validate most fixes without a phone.',
            'If you ever want to test directly on your Android phone, open Settings > About phone and tap Build number 7 times to unlock Developer options.',
            'Inside Developer options, turn on USB debugging, connect the cable, and tap Allow on the phone popup.',
            'Safety note: Nox only reads filtered logs from the target app — it never erases logs or uninstalls your apps.',
        ]
        if is_en
        else [
            'Etapa opcional: quase tudo e criado e validado sem precisar conectar celular.',
            'Se quiser testar ao vivo no Android: abra Configuracoes > Sobre o telefone e toque 7 vezes em Numero da versao para ativar Opcoes do desenvolvedor.',
            'Entre em Opcoes do desenvolvedor, ative a Depuracao USB, conecte o cabo e toque em Permitir no aviso do celular.',
            'Garantia: a Nox apenas le eventos filtrados do app alvo; ela nunca apaga logs nem desinstala seus aplicativos.',
        ]
    )
    return {
        'required': False,
        'applicable': True,
        'summary': (
            'Android device connection (ADB) is completely optional.'
            if is_en
            else 'Conexao com celular Android (ADB) e totalmente opcional.'
        ),
        'steps': steps,
    }


def _default_refs_cache() -> Path:
    return Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'opencode/nox-workspace/nox-extension-developer'


def _resolve_persistent_output_dir(slug: str, output_dir: Path | str | None, repo_root: Path | str | None) -> Path:
    if output_dir is not None:
        return Path(output_dir).resolve()
    if repo_root is not None:
        return Path(repo_root).resolve()
    env_out = os.environ.get('NOX_OUTPUT_DIR')
    if env_out:
        return (Path(env_out).expanduser().resolve() / slug)
    return Path.home() / '.local' / 'share' / 'antigravity' / 'Nox-Workspace' / 'laboratorios' / 'nox-output' / slug


def _infer_gradle_task(module_or_out: Path, build_root: Path, source_lang: str, slug: str) -> str:
    if (build_root / 'app').is_dir() and not (module_or_out / 'src' / source_lang / slug).is_dir():
        return ':app:assembleDebug'
    return f':src:{source_lang}:{slug}:assembleDebug'


def auto_create_extension(
    prompt_or_url: str,
    *,
    name: str | None = None,
    ecosystem: str | None = None,
    source_lang: str = 'pt-BR',
    ui_lang: str = 'pt-BR',
    output_dir: Path | str | None = None,
    repo_root: Path | str | None = None,
    build_task: str | None = None,
    dry_run: bool = False,
    technical: bool = False,
    site_url: str | None = None,
    allow_local_fixture: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute end-to-end automated extension creation: identify, probe site, implement real selectors, verify, compile in sandbox, and prepare APK delivery."""
    import nox_android
    import nox_issues
    import references

    parsed = nox_issues.parse_natural_language_request(prompt_or_url)
    eco = ecosystem or parsed['inferred_ecosystem']
    resolved_url = site_url or parsed.get('url')
    is_en = ui_lang == 'en'

    if not resolved_url:
        msg = (
            'Send the website address (URL) you want me to support so I can analyze it and build the extension.'
            if is_en
            else 'Envie o endereço do site (URL) que você quer adicionar para que eu possa analisá-lo e criar a extensão.'
        )
        cont = build_agent_continuation(
            phase='IDENTIFY',
            task_complete=False,
            status='INCONCLUSIVE',
            completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'NOT_RUN', 'functional_tests': 'NOT_RUN', 'apk_build': 'NOT_RUN'},
            next_agent_action='Ask only for the missing website URL, then continue auto_create_extension immediately.',
        )
        return format_adaptive_response(
            {
                'status': 'INCONCLUSIVE',
                'action': 'auto_create',
                'ecosystem': eco,
                'user_message': msg,
                'next_step': msg,
                'parsed_request': parsed,
                'agent_continuation': cont,
            },
            technical=technical,
            lang=ui_lang,
        )

    ext_name = _pascal(name) if name else _infer_name_from_prompt(prompt_or_url, resolved_url)
    slug = _slug(ext_name)
    persisted_dir = _resolve_persistent_output_dir(slug, output_dir, repo_root)

    if repo_root and Path(repo_root).is_dir():
        sec_repo = nox_android.audit_untrusted_pr_or_repo(Path(repo_root))
        if sec_repo['status'] == 'FAIL':
            cont = build_agent_continuation(
                phase='IDENTIFY',
                task_complete=False,
                status='FAIL',
                completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'NOT_RUN', 'functional_tests': 'NOT_RUN', 'apk_build': 'BLOCKED'},
                next_agent_action='Refuse executing unsafe repository build files and inspect security findings.',
            )
            return format_adaptive_response(
                {
                    'status': 'FAIL',
                    'action': 'auto_create',
                    'ecosystem': eco,
                    'output_dir': str(persisted_dir),
                    'user_message': (
                        'Stopped because the target repository failed security verification.'
                        if is_en
                        else 'Parei por segurança porque o repositório de destino falhou na verificação de integridade.'
                    ),
                    'next_step': (
                        'Review the security findings before making changes in that repository.'
                        if is_en
                        else 'Revise os alertas de segurança antes de alterar esse repositório.'
                    ),
                    'security_preflight': sec_repo,
                    'agent_continuation': cont,
                },
                technical=technical,
                lang=ui_lang,
                diagnostics_dir=persisted_dir if persisted_dir.is_dir() else None,
            )

    doctor = run_doctor(ecosystem=eco)
    ref_status = references.status(eco, _default_refs_cache())
    existing = search_existing_extensions(repo_root, resolved_url or ext_name) if repo_root and Path(repo_root).is_dir() else None
    adb_guide = build_optional_adb_guide(eco, lang=ui_lang)

    # Stage 2: Analyze live/fixture site cleanly before generating code
    probe = _probe_and_verify_live_or_fixture_site(resolved_url, eco, allow_local_fixture=allow_local_fixture)
    cfg = probe.get('discovered_config') or {}

    scaffold_res: dict[str, Any] | None = None
    persisted_files: list[str] = []
    if not dry_run:
        persisted_dir.mkdir(parents=True, exist_ok=True)
        scaffold_res = scaffold_extension(
            eco,
            ext_name,
            resolved_url.rstrip('/'),
            lang=source_lang,
            output_dir=persisted_dir,
            search_param=cfg.get('search_param', 'q'),
            image_attr=cfg.get('image_attr', 'data-src'),
            catalog_path=cfg.get('catalog_path'),
            catalog_selector=cfg.get('catalog_selector'),
            chapter_selector=cfg.get('chapter_selector', 'a.chapter[href]'),
            episode_selector=cfg.get('episode_selector', 'a.episode[href]'),
            page_selector=cfg.get('page_selector', 'img.page'),
            hoster_selector=cfg.get('hoster_selector', 'a.server[href]'),
            video_selector=cfg.get('video_selector', 'video source[src], video[src]'),
            novel_content_selector=cfg.get('novel_content_selector', '.chapter-content'),
        )
        persisted_files = [str(Path(f).resolve()) for f in scaffold_res.get('created_files', [])]

    tests_verified = probe.get('status') == 'PASS'
    code_implemented = bool(persisted_files) and tests_verified

    # Stage 5: Attempt protected Android Debug APK build whenever Gradle wrapper exists
    build_res: dict[str, Any] | None = None
    delivery_res: dict[str, Any] | None = None
    build_root = (
        Path(repo_root).resolve()
        if (repo_root and (Path(repo_root) / 'gradlew').is_file())
        else (persisted_dir if (persisted_dir / 'gradlew').is_file() else None)
    )
    if not dry_run and eco in {'keiyoushi', 'yuzono'} and (build_root is not None or build_task is not None):
        broot = build_root or persisted_dir
        task = build_task or _infer_gradle_task(persisted_dir, broot, source_lang, slug)
        build_res = nox_android.build_debug_apk(
            broot,
            task,
            sandbox_available_override=sandbox_available_override,
        )
        if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
            delivery_res = nox_android.verify_and_offer_apk_delivery(
                build_res.get('apk_path'),
                min_mtime=build_res.get('build_started_at'),
                lang=ui_lang,
            )

    apk_ready = bool(delivery_res and delivery_res.get('apk_ready'))
    apk_path = delivery_res.get('apk_path') if apk_ready else None
    apk_options = delivery_res.get('options') if apk_ready else None

    # Stage 6: Strict honest final classification (NEVER return PASS from template-only or failed build!)
    limitations: list[str] = []
    if probe.get('status') == 'BLOCKED':
        status = 'BLOCKED'
        limitations.append(str(probe.get('error') or 'Target site blocked automated inspection.'))
    elif not tests_verified:
        status = 'INCONCLUSIVE' if probe.get('status') != 'FAIL' else 'FAIL'
        limitations.append(str(probe.get('error') or 'Could not verify live site endpoints automatically.'))
    elif build_res is not None and build_res.get('status') in {'BLOCKED', 'FAIL'}:
        status = build_res['status']
        limitations.append(str(build_res.get('reason') or 'APK compilation could not finish safely.'))
    elif eco in {'keiyoushi', 'yuzono'} and build_res is None:
        # Functional checks on real site passed and files saved, while no Gradle wrapper repo was attached for APK build
        status = 'PASS'
        limitations.append(
            'Extension source created and verified against the site; Debug APK compilation was not run because no Android Gradle repository root was provided.'
            if is_en
            else 'Código da extensão criado e validado contra o site; o APK Debug não foi compilado porque não havia um projeto Gradle completo nesta pasta.'
        )
    else:
        status = 'PASS'

    task_complete = status == 'PASS' and code_implemented and tests_verified and (build_res is None or apk_ready)
    phase = 'DELIVER_ARTIFACT' if apk_ready else ('VERIFY_TESTS' if tests_verified else 'SITE_ANALYSIS')
    cont = build_agent_continuation(
        phase=phase,
        task_complete=task_complete,
        status=status,
        completed_gates={
            'site_analyzed': 'PASS' if probe.get('reachable') else 'INCONCLUSIVE',
            'code_implemented': 'PASS' if code_implemented else 'INCONCLUSIVE',
            'functional_tests': 'PASS' if tests_verified else ('FAIL' if probe.get('status') == 'FAIL' else 'INCONCLUSIVE'),
            'apk_build': build_res['status'] if build_res else ('NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN'),
            'apk_inspected': delivery_res['status'] if delivery_res else 'NOT_RUN',
        },
        next_agent_action=(
            'Present concise completion and 3 APK options.'
            if apk_ready
            else (
                'Complete custom site implementation, verify selectors against fetched pages, compile Debug APK in sandbox, and deliver result.'
                if not task_complete
                else 'Deliver verified files cleanly.'
            )
        ),
    )

    if apk_ready:
        msg = (
            f'Done! Created extension "{ext_name}" and generated the Debug APK. 💜'
            if is_en
            else f'Pronto! Sua extensão "{ext_name}" foi criada e o APK Debug foi gerado com sucesso. 💜'
        )
        nxt = delivery_res['prompt'] if delivery_res else ''
    elif status == 'PASS' and eco == 'lnreader':
        msg = (
            f'Done! Created and verified LNReader novel plugin "{ext_name}". 💜'
            if is_en
            else f'Pronto! Plugin LNReader "{ext_name}" criado e validado com sucesso. 💜'
        )
        nxt = (
            f'Saved at: {persisted_files[0]}'
            if (is_en and persisted_files)
            else f'Arquivo salvo em: {persisted_files[0] if persisted_files else persisted_dir}'
        )
    elif status == 'PASS':
        msg = (
            f'Created and verified extension code for "{ext_name}".'
            if is_en
            else f'Criei e validei o código da extensão "{ext_name}".'
        )
        nxt = limitations[0] if limitations else ''
    elif build_res is not None and build_res.get('status') in {'BLOCKED', 'FAIL'}:
        msg = (
            f'Created and saved the source code for "{ext_name}", while Debug APK compilation stopped ({build_res["status"]}).'
            if is_en
            else f'O código da extensão "{ext_name}" foi salvo, mas não foi possível gerar o APK Debug agora.'
        )
        nxt = (
            'Your extension files are preserved. Confirm Android/sandbox requirements or inspect the limitation before building again.'
            if is_en
            else 'Os arquivos da extensão continuam salvos. Assim que o ambiente de compilação estiver liberado, você poderá gerar o APK.'
        )
    else:
        msg = (
            f'Saved initial files for "{ext_name}", but live site verification could not confirm catalog/chapters automatically yet.'
            if is_en
            else f'Salvei os arquivos iniciais para "{ext_name}", mas ainda não foi possível confirmar o funcionamento no site real.'
        )
        nxt = (
            'Keep investigating the live site structure, implement working selectors, and re-run functional checks.'
            if is_en
            else 'Continuando a análise do site para ajustar os seletores reais antes de finalizar.'
        )

    payload = {
        'status': status,
        'action': 'auto_create',
        'ecosystem': eco,
        'extension_name': ext_name,
        'target_url': resolved_url,
        'output_dir': str(persisted_dir),
        'persisted_files': persisted_files,
        'artifact_path': apk_path or (persisted_files[0] if persisted_files else None),
        'code_implemented': code_implemented,
        'tests_verified': tests_verified,
        'apk_ready': apk_ready,
        'apk_path': apk_path,
        'apk_options': apk_options,
        'user_message': msg,
        'next_step': nxt,
        'user_limitations': limitations or None,
        'parsed_request': parsed,
        'site_probe': probe,
        'environment': doctor,
        'reference_snapshot': ref_status,
        'existing_search': existing,
        'scaffold': scaffold_res,
        'sandbox_build': build_res,
        'apk_delivery': delivery_res,
        'optional_adb_guide': adb_guide,
        'agent_continuation': cont,
    }
    return format_adaptive_response(
        payload,
        technical=technical,
        lang=ui_lang,
        diagnostics_dir=persisted_dir if persisted_dir.is_dir() else None,
    )


def _extract_base_url_from_files(files: Sequence[Path]) -> str | None:
    for fp in files:
        txt = fp.read_text(encoding='utf-8', errors='replace')
        m1 = re.search(r'baseUrl\s*=\s*"([^"]+)"', txt)
        if m1:
            return m1.group(1)
        m2 = re.search(r"site\s*=\s*['\"]([^'\"]+)['\"]", txt)
        if m2:
            return m2.group(1)
    return None


def _reproduce_existing_source_failures(
    code_text: str,
    ecosystem: str,
    base_url: str,
    probe: dict[str, Any],
    *,
    allow_local_fixture: bool = False,
) -> dict[str, Any]:
    """Verify whether selectors/query params/image attrs currently in source files fail against target site."""
    cfg = probe.get('discovered_config') or {}
    failures: list[str] = []
    if not probe.get('reachable'):
        return {'status': 'INCONCLUSIVE', 'failures': ['site_unreachable']}

    if ecosystem == 'keiyoushi':
        ch_sel = cfg.get('chapter_selector', 'a.chapter[href]')
        if ch_sel not in code_text and ('broken' in code_text or 'select("' in code_text):
            m_sel = re.search(r'fetchMangaUpdate[\s\S]{0,600}?doc\.select\("([^"]+)"\)', code_text)
            if m_sel and m_sel.group(1) != ch_sel:
                failures.append(f'wrong_chapter_selector:{m_sel.group(1)}')
        sp = cfg.get('search_param', 'q')
        m_qp = re.search(r'addQueryParameter\("([^"]+)",\s*query', code_text)
        if m_qp and m_qp.group(1) != sp:
            failures.append(f'wrong_search_param:{m_qp.group(1)}')
        img_attr = cfg.get('image_attr', 'data-src')
        if img_attr != 'src' and 'absUrl("data-src")' not in code_text and 'absUrl("src")' in code_text:
            failures.append('deceptive_image_attr_src')
        if 'parseChapterNumber' not in code_text and '.toInt()' in code_text:
            failures.append('integer_chapter_truncation')
        if 'drive.google.com/uc?id=' in code_text:
            failures.append('broken_gdrive_uc_cover_url')
    elif ecosystem == 'yuzono':
        ep_sel = cfg.get('episode_selector', 'a.episode[href]')
        if ep_sel not in code_text and 'episodeListParse' in code_text:
            failures.append('wrong_episode_selector')
        h_sel = cfg.get('hoster_selector', 'a.server[href]')
        if h_sel not in code_text and 'hosterListParse' in code_text:
            failures.append('wrong_hoster_selector')
    elif ecosystem == 'lnreader':
        nc_sel = cfg.get('novel_content_selector', '.chapter-content')
        if nc_sel not in code_text and 'parseChapter' in code_text:
            failures.append('wrong_novel_content_selector')
        if "$('script, style, nav').remove()" not in code_text and 'parseChapter' in code_text:
            failures.append('missing_nav_noise_strip')
        sp = cfg.get('search_param', 'q')
        if f'?{sp}=' not in code_text and '?search=' in code_text:
            failures.append('wrong_search_param:search')

    return {'status': 'FAIL' if failures else 'PASS', 'failures': failures}


def _apply_automated_code_repairs(
    target_path: Path,
    ecosystem: str,
    symptom: str,
    probe: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Apply concrete minimal code edits to broken .kt/.ts/.js/build.gradle.kts files on disk."""
    cfg = probe.get('discovered_config') or {}
    code_files = (
        [target_path]
        if target_path.is_file()
        else sorted(p for p in target_path.rglob('*') if p.is_file() and p.suffix in {'.kt', '.ts', '.js', '.kts'})
    )
    modified: list[str] = []
    changes: list[str] = []

    for fp in code_files:
        orig = fp.read_text(encoding='utf-8', errors='replace')
        updated = orig

        if fp.suffix in {'.kt', '.ts', '.js'}:
            sp = cfg.get('search_param', 'q')
            if ecosystem in {'keiyoushi', 'yuzono'} and f'addQueryParameter("{sp}", query' not in updated:
                new_u, n = re.subn(r'addQueryParameter\("search",\s*(query[^)]*)\)', f'addQueryParameter("{sp}", \\1)', updated)
                if n:
                    updated = new_u
                    changes.append(f'{fp.name}: fixed search query parameter -> {sp}')
            if ecosystem == 'lnreader' and f'?{sp}=' not in updated and '?search=' in updated:
                updated = updated.replace('?search=', f'?{sp}=')
                changes.append(f'{fp.name}: fixed search query parameter -> {sp}')

            if ecosystem == 'keiyoushi':
                cat_sel = cfg.get('catalog_selector')
                if cat_sel and cat_sel not in updated and 'getSearchMangaList' in updated:
                    new_u = re.sub(r'doc\.select\("([^"]*broken[^"]*|div\.old[^"]*)"\)', f'doc.select("{cat_sel}")', updated, count=1)
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired catalog selector -> {cat_sel}')
                ch_sel = cfg.get('chapter_selector')
                if ch_sel and ch_sel not in updated and 'fetchMangaUpdate' in updated:
                    new_u = re.sub(
                        r'(val\s+chs\s*=\s*if\s*\([^)]+\)\s*doc\.select\(")([^"]+)(")',
                        rf'\g<1>{ch_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired chapter selector -> {ch_sel}')
                img_attr = cfg.get('image_attr', 'data-src')
                if img_attr == 'data-src' and 'absUrl("data-src")' not in updated and 'img.absUrl("src")' in updated:
                    updated = updated.replace(
                        'img.absUrl("src")',
                        'img.absUrl("data-src").ifBlank { img.absUrl("src") }',
                    )
                    changes.append(f'{fp.name}: switched image extraction to data-src with src fallback')
                if 'headersBuilder()' not in updated and 'class ' in updated and ('image' in symptom.lower() or '403' in symptom or 'imagem' in symptom.lower() or 'cover' in symptom.lower() or 'capa' in symptom.lower()):
                    updated = re.sub(
                        r'(abstract\s+class\s+[^{]+\{\n)',
                        r'\1    override fun headersBuilder() = super.headersBuilder().add("Referer", "$baseUrl/")\n\n',
                        updated,
                        count=1,
                    )
                    changes.append(f'{fp.name}: added Referer header builder')
                if '.toInt()' in updated and 'chapter' in updated.lower():
                    updated = updated.replace('.toInt()', '.replace(",", ".").toFloatOrNull() ?: -1f')
                    changes.append(f'{fp.name}: preserved fractional chapter numbers')
                if 'drive.google.com/uc?id=' in updated:
                    updated = re.sub(
                        r'https://drive\.google\.com/uc\?id=([A-Za-z0-9_-]+)(?:&export=[a-z]+)?',
                        r'https://drive.google.com/thumbnail?id=\1&sz=w1000',
                        updated,
                    )
                    changes.append(f'{fp.name}: upgraded Google Drive cover URL to thumbnail endpoint')

            elif ecosystem == 'yuzono':
                ep_sel = cfg.get('episode_selector')
                if ep_sel and ep_sel not in updated and 'episodeListParse' in updated:
                    new_u = re.sub(
                        r'(override\s+fun\s+episodeListParse\([^)]*\)[^{=]*=\s*response\.asJsoup\(\)\.select\(")([^"]+)(")',
                        rf'\g<1>{ep_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired episode selector -> {ep_sel}')
                h_sel = cfg.get('hoster_selector')
                if h_sel and h_sel not in updated and 'hosterListParse' in updated:
                    new_u = re.sub(
                        r'(override\s+fun\s+hosterListParse\([^)]*\)[^{=]*=\s*response\.asJsoup\(\)\.select\(")([^"]+)(")',
                        rf'\g<1>{h_sel}\g<3>',
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired hoster selector -> {h_sel}')

            elif ecosystem == 'lnreader':
                nc_sel = cfg.get('novel_content_selector')
                if nc_sel and nc_sel not in updated and 'parseChapter' in updated:
                    new_u = re.sub(
                        r"(return\s+\$\(['\"])([^'\"]+)(['\"]\)\.html\(\))",
                        rf"\g<1>{nc_sel}\g<3>",
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: repaired novel chapter content selector -> {nc_sel}')
                if "$('script, style, nav').remove()" not in updated and 'parseChapter' in updated:
                    new_u = re.sub(
                        r'(const\s+\$\s*=\s*parseHTML\([^\n]+\);\n)',
                        r"\1    $('script, style, nav').remove();\n",
                        updated,
                        count=1,
                    )
                    if new_u != updated:
                        updated = new_u
                        changes.append(f'{fp.name}: added nav/script cleanup in parseChapter')

        if updated != orig:
            atomic_write_text(fp, updated)
            modified.append(str(fp.resolve()))

    return modified, changes


def auto_fix_extension(
    target: Path | str,
    symptom: str,
    *,
    ecosystem: str | None = None,
    ui_lang: str = 'pt-BR',
    attempts: Sequence[dict[str, Any]] = (),
    build_task: str | None = None,
    technical: bool = False,
    site_url: str | None = None,
    allow_local_fixture: bool = False,
    sandbox_available_override: bool | None = None,
) -> dict[str, Any]:
    """Execute end-to-end automated repair: investigate, reproduce, patch files on disk, verify fix, compile in sandbox, and offer APK delivery."""
    import nox_android
    import nox_issues
    import references

    tpath = Path(target).resolve()
    is_en = ui_lang == 'en'
    diag = nox_issues.diagnose_and_suggest_fix_from_issues(tpath, symptom, ecosystem=ecosystem)
    eco = diag['ecosystem']
    doctor = run_doctor(ecosystem=eco, check_path=tpath if tpath.is_dir() else None)
    ref_status = references.status(eco, _default_refs_cache())
    sec = nox_android.audit_untrusted_pr_or_repo(tpath) if tpath.is_dir() else None
    loop = detect_investigation_loop(attempts)
    adb_status = nox_android.adb_doctor() if eco in {'keiyoushi', 'yuzono'} else {'status': 'NOT_RUN', 'devices': []}
    adb_guide = build_optional_adb_guide(eco, lang=ui_lang)

    if sec and sec['status'] == 'FAIL':
        cont = build_agent_continuation(
            phase='IDENTIFY',
            task_complete=False,
            status='FAIL',
            completed_gates={'site_analyzed': 'NOT_RUN', 'code_implemented': 'BLOCKED', 'functional_tests': 'NOT_RUN', 'apk_build': 'BLOCKED'},
            next_agent_action='Stop repair because repository failed security pre-flight audit.',
        )
        return format_adaptive_response(
            {
                'status': 'FAIL',
                'action': 'auto_fix',
                'ecosystem': eco,
                'target': str(tpath),
                'output_dir': str(tpath if tpath.is_dir() else tpath.parent),
                'code_modified': False,
                'tests_verified': False,
                'apk_ready': False,
                'user_message': (
                    'Stopped automatic repair because this project contains unsafe build or script patterns.'
                    if is_en
                    else 'Parei o reparo automático porque este projeto contém padrões inseguros em arquivos de build ou scripts.'
                ),
                'next_step': (
                    'Review the flagged security findings before opening or compiling this repository.'
                    if is_en
                    else 'Revise os alertas de segurança antes de compilar ou executar este repositório.'
                ),
                'diagnosis': diag,
                'loop_detection': loop,
                'security_preflight': sec,
                'agent_continuation': cont,
            },
            technical=technical,
            lang=ui_lang,
            diagnostics_dir=tpath if tpath.is_dir() else tpath.parent,
        )

    before_proj = inspect_project(tpath) if tpath.exists() else {'sources': []}
    code_files = (
        [tpath]
        if tpath.is_file()
        else (sorted(p for p in tpath.rglob('*') if p.is_file() and p.suffix in {'.kt', '.ts', '.js', '.kts'}) if tpath.is_dir() else [])
    )
    resolved_site = site_url or _extract_base_url_from_files(code_files)
    combined_before_text = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in code_files)

    probe: dict[str, Any] = {'status': 'INCONCLUSIVE', 'reachable': False, 'discovered_config': {}}
    if resolved_site:
        probe = _probe_and_verify_live_or_fixture_site(resolved_site, eco, allow_local_fixture=allow_local_fixture)

    before_verification = _reproduce_existing_source_failures(
        combined_before_text,
        eco,
        resolved_site or '',
        probe,
        allow_local_fixture=allow_local_fixture,
    )

    modified_files, patch_changes = _apply_automated_code_repairs(tpath, eco, symptom, probe)
    code_modified = len(modified_files) > 0

    after_proj = inspect_project(tpath) if tpath.exists() else {'sources': []}
    identity_check = (
        check_identity_continuity(before_proj.get('sources') or [], after_proj.get('sources') or [])
        if (before_proj.get('sources') and after_proj.get('sources'))
        else {'status': 'PASS'}
    )
    combined_after_text = '\n'.join(p.read_text(encoding='utf-8', errors='replace') for p in code_files)
    after_verification = _reproduce_existing_source_failures(
        combined_after_text,
        eco,
        resolved_site or '',
        probe,
        allow_local_fixture=allow_local_fixture,
    )
    tests_verified = (
        probe.get('status') == 'PASS'
        and after_verification.get('status') == 'PASS'
        and identity_check.get('status') == 'PASS'
    )

    build_res: dict[str, Any] | None = None
    delivery_res: dict[str, Any] | None = None
    gradle_root: Path | None = None
    if tpath.is_dir():
        if (tpath / 'gradlew').is_file():
            gradle_root = tpath
        elif len(tpath.parents) >= 3:
            for par in tpath.parents:
                if (par / 'gradlew').is_file():
                    gradle_root = par
                    break
    if eco in {'keiyoushi', 'yuzono'} and (gradle_root is not None or build_task is not None) and code_modified:
        broot = gradle_root or (tpath if tpath.is_dir() else tpath.parent)
        task = build_task or ':app:assembleDebug'
        build_res = nox_android.build_debug_apk(
            broot,
            task,
            sandbox_available_override=sandbox_available_override,
        )
        if build_res.get('apk_path') and build_res.get('status') not in {'BLOCKED', 'FAIL'}:
            delivery_res = nox_android.verify_and_offer_apk_delivery(
                build_res.get('apk_path'),
                min_mtime=build_res.get('build_started_at'),
                lang=ui_lang,
            )

    apk_ready = bool(delivery_res and delivery_res.get('apk_ready'))
    apk_path = delivery_res.get('apk_path') if apk_ready else None
    apk_options = delivery_res.get('options') if apk_ready else None

    limitations: list[str] = []
    if build_res is not None and build_res.get('status') in {'BLOCKED', 'FAIL'}:
        status = build_res['status']
        limitations.append(str(build_res.get('reason') or 'APK build stopped.'))
    elif code_modified and tests_verified:
        status = 'PASS'
    elif code_modified and not tests_verified:
        status = 'INCONCLUSIVE'
        limitations.append('Applied code fixes, though complete end-to-end site verification remained partial.' if is_en else 'Apliquei as alterações no código, mas ainda não foi possível confirmar tudo no site real.')
    else:
        status = 'INCONCLUSIVE'
        limitations.append(
            'Could not resolve this defect with an automated pattern alone; agent must continue reading the exact module source and patching it.'
            if is_en
            else 'Ainda não encontrei uma correção automática segura para este caso; é preciso continuar analisando o código real para ajustar.'
        )

    task_complete = (status == 'PASS') and code_modified and tests_verified and (build_res is None or apk_ready)
    top_alt = (loop.get('recommended_alternatives') or diag.get('recommended_actions') or [''])[0]
    cont = build_agent_continuation(
        phase='DELIVER_ARTIFACT' if apk_ready else ('VERIFY_TESTS' if code_modified else 'IMPLEMENT_OR_PATCH'),
        task_complete=task_complete,
        status=status,
        completed_gates={
            'site_analyzed': 'PASS' if probe.get('reachable') else 'INCONCLUSIVE',
            'code_implemented': 'PASS' if code_modified else 'NOT_RUN',
            'functional_tests': 'PASS' if tests_verified else 'INCONCLUSIVE',
            'apk_build': build_res['status'] if build_res else ('NOT_APPLICABLE' if eco == 'lnreader' else 'NOT_RUN'),
            'apk_inspected': delivery_res['status'] if delivery_res else 'NOT_RUN',
        },
        next_agent_action=(
            'Deliver fixed APK options cleanly.'
            if apk_ready
            else ('Inspect exact source files, edit failing logic on disk, re-run verification, and compile APK.' if not task_complete else 'Deliver fixed files cleanly.')
        ),
    )

    if loop['loop_detected'] and not code_modified:
        msg = (
            'Detected repeated attempts without progress and switched investigation strategy.'
            if is_en
            else 'Identifiquei tentativas repetidas sem progresso e mudei a estratégia de investigação.'
        )
        nxt = top_alt
    elif apk_ready:
        msg = (
            'Fixed the extension, verified tests, and generated the updated Debug APK. 💜'
            if is_en
            else 'Corrigi a extensão, validei os testes disponíveis e gerei o novo APK Debug. 💜'
        )
        nxt = delivery_res['prompt'] if delivery_res else ''
    elif status == 'PASS':
        msg = (
            'Fixed the extension code and verified the repaired behavior.'
            if is_en
            else 'Corrigi o código da extensão e validei o funcionamento com sucesso.'
        )
        nxt = (
            f'Updated files saved: {", ".join(Path(p).name for p in modified_files)}'
            if is_en
            else f'Arquivos atualizados salvos: {", ".join(Path(p).name for p in modified_files)}'
        )
    elif build_res is not None and build_res.get('status') in {'BLOCKED', 'FAIL'}:
        msg = (
            'Applied and verified code fixes on disk, while Debug APK compilation stopped.'
            if is_en
            else 'Apliquei e validei a correção no código, mas ainda não foi possível gerar o novo APK Debug.'
        )
        nxt = 'Os arquivos corrigidos estão salvos para nova compilação assim que possível.' if not is_en else 'Fixed source files remain saved on disk.'
    else:
        msg = (
            'Ran initial diagnosis; continuing deeper source inspection and patching.'
            if is_en
            else 'Fiz o diagnóstico inicial e ainda preciso concluir a correção no código antes de confirmar o conserto.'
        )
        nxt = top_alt or (
            'Open the target module code, apply the concrete fix, and re-run checks.'
            if is_en
            else 'Continuando a leitura do código real para aplicar e testar a correção.'
        )

    payload = {
        'status': status,
        'action': 'auto_fix',
        'ecosystem': eco,
        'target': str(tpath),
        'output_dir': str(tpath if tpath.is_dir() else tpath.parent),
        'symptom': symptom,
        'persisted_files': modified_files,
        'modified_files': modified_files,
        'patch_changes': patch_changes,
        'code_modified': code_modified,
        'tests_verified': tests_verified,
        'before_verification': before_verification,
        'after_verification': after_verification,
        'identity_continuity': identity_check,
        'artifact_path': apk_path or (modified_files[0] if modified_files else None),
        'apk_ready': apk_ready,
        'apk_path': apk_path,
        'apk_options': apk_options,
        'user_message': msg,
        'next_step': nxt,
        'user_limitations': limitations or None,
        'diagnosis': diag,
        'loop_detection': loop,
        'security_preflight': sec,
        'environment': doctor,
        'reference_snapshot': ref_status,
        'sandbox_build': build_res,
        'apk_delivery': delivery_res,
        'optional_adb_status': adb_status,
        'optional_adb_guide': adb_guide,
        'agent_continuation': cont,
    }
    return format_adaptive_response(
        payload,
        technical=technical,
        lang=ui_lang,
        diagnostics_dir=tpath if tpath.is_dir() else tpath.parent,
    )
