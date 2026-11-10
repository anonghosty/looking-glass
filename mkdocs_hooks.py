"""MkDocs hooks for the documentation site.

* A link from a guide to a file outside docs/ (the installer, a script, a folder's README) has no page on the site, so
  it is pointed at that file on GitHub instead of breaking.
* A line ending in <!-- film: NAME --> (or <!-- film: NAME start=SECONDS -->) becomes a player for that film from
  extra.films in mkdocs.yml: the poster, a play button, the chapters as buttons. YouTube (the privacy-enhanced
  youtube-nocookie.com) loads only when the reader presses play. On GitHub the same line shows a clickable poster.
"""
import html
import os
import posixpath
import re

REPO = "https://github.com/anonghosty/looking-glass"
MD_LINK = re.compile(r"(\]\()([^)\s]+?)(\))")
HTML_ATTR = re.compile(r"""((?:href|src)=["'])([^"']+)(["'])""")


def _outside(target, page_dir, root):
    """The repository path of a relative link that leaves docs/, or None for anything else."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith(("#", "/")):
        return None
    path, _, anchor = target.partition("#")
    repo_path = posixpath.normpath(posixpath.join("docs", page_dir, path))
    if repo_path.startswith("docs/") or repo_path == "docs":
        return None
    kind = "tree" if os.path.isdir(os.path.join(root, repo_path)) else "blob"
    return f"{REPO}/{kind}/main/{repo_path}" + (f"#{anchor}" if anchor else "")


FILM_LINE = re.compile(r"^.*<!--\s*film:\s*([a-z0-9-]+)(?:\s+start=(\d+))?(?:\s+(compact))?\s*-->\s*$", re.M)
PLAY = ('<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5.5v13a1 1 0 0 0 1.52.85l10.4-6.5a1 1 0 0 0 0-1.7'
        'L9.52 4.65A1 1 0 0 0 8 5.5Z" fill="currentColor"/></svg>')


def _clock(s):
    return f"{s // 60}:{s % 60:02d}"


def _film(name, start, compact, films, base):
    f = films.get(name)
    if not f:
        raise ValueError(f"film '{name}' is not in extra.films (mkdocs.yml)")
    e = html.escape
    chapters = "" if compact else "".join(
        f'<button type="button" class="lg-film-ch" data-t="{t}"><span>{_clock(t)}</span>{e(label)}</button>'
        for t, label in f.get("chapters", []))
    start_note = f" · starts at {_clock(start)}" if start else ""
    return (
        f'<figure class="lg-film{" lg-film--compact" if compact else ""}" data-yt="{e(f["id"])}" data-start="{start}">'
        f'<div class="lg-film-frame"><button type="button" class="lg-film-poster" aria-label="Play the film: {e(f["title"])}">'
        f'<img src="{base}media/films/{e(name)}.jpg" alt="" loading="lazy" width="1280" height="720">'
        f'<span class="lg-film-play">{PLAY}</span><span class="lg-film-len">{e(f["length"])}</span></button></div>'
        f'<figcaption><span class="lg-film-eyebrow">Film · {e(f["length"])} · {e(f.get("sound", ""))}{start_note}</span>'
        f'<b class="lg-film-title">{e(f["title"])}</b>'
        + (f'<span class="lg-film-chs">{chapters}</span>' if chapters else "")
        + f'<a class="lg-film-yt" href="https://www.youtube.com/watch?v={e(f["id"])}" rel="noopener">Watch on YouTube</a>'
        '</figcaption></figure>')


def on_page_markdown(markdown, page, config, files):
    root = os.path.dirname(os.path.abspath(config["config_file_path"]))
    page_dir = posixpath.dirname(page.file.src_uri)
    films = (config.get("extra") or {}).get("films") or {}
    base = "../" * page.url.count("/")              # directory URLs: USER_GUIDE/ -> ../, the home page -> ""

    def sub(m):
        url = _outside(m.group(2), page_dir, root)
        return f"{m.group(1)}{url}{m.group(3)}" if url else m.group(0)
    markdown = HTML_ATTR.sub(sub, MD_LINK.sub(sub, markdown))
    return FILM_LINE.sub(lambda m: "\n" + _film(m.group(1), int(m.group(2) or 0), bool(m.group(3)), films, base) + "\n", markdown)
