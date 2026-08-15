#!/usr/bin/env python3
"""
Generate embedded web assets from src/web/ui/* into src/web/ui/gen/*.hpp
"""

from pathlib import Path
import os
import re
import sys


def detect_project_root() -> Path:
    try:
        from SCons.Script import Import  # type: ignore

        Import("env")
        prj = env.subst("$PROJECT_DIR")  # type: ignore[name-defined]
        if prj:
            return Path(prj).resolve()
    except Exception:
        pass

    if "__file__" in globals():
        return Path(__file__).resolve().parents[1]
    return Path.cwd().resolve()


PROJECT_ROOT = detect_project_root()
IN_DIR = PROJECT_ROOT / "src" / "web" / "ui"
OUT_DIR = IN_DIR / "gen"
EXT_KIND = {".html": "HTML", ".js": "JS", ".css": "CSS"}


def sym_from_file(path: Path, kind: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", path.stem).upper() + f"_{kind}_GEN"


def header_name(path: Path, kind: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", path.stem).lower() + f"_{kind.lower()}_gen.hpp"


def run() -> None:
    print(f"[webui] SRC={PROJECT_ROOT}")
    print(f"[webui] IN_DIR={IN_DIR}")
    print(f"[webui] OUT_DIR={OUT_DIR}")

    if not IN_DIR.exists():
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        sys.exit("[webui] Missing src/web/ui")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[webui] Cleaning output directory {OUT_DIR}...")
    for item in OUT_DIR.iterdir():
        if item.is_file() and item.suffix == ".hpp":
            try:
                item.unlink()
            except PermissionError:
                # On OneDrive/AV transient locks, keep existing file and continue.
                print(f"[webui] skip locked file: {item.name}")

    generated = []
    for src in sorted(IN_DIR.iterdir()):
        if src.is_dir() or src.name == "gen":
            continue
        kind = EXT_KIND.get(src.suffix.lower())
        if not kind:
            continue

        symbol = sym_from_file(src, kind)
        out = OUT_DIR / header_name(src, kind)
        content = src.read_text(encoding="utf-8")
        content_size = len(content.encode("utf-8"))
        size_sym = symbol + "_SIZE"

        header = (
            f"/* auto-generated from {src.name} */\n"
            "#pragma once\n"
            f"static const char* {symbol} = R\"HTML(\n"
            f"{content}\n"
            ")HTML\";\n\n"
            "// Compile-time size constant (actual content length)\n"
            f"static constexpr size_t {size_sym} = {content_size};\n"
        )

        out.write_text(header, encoding="utf-8")
        generated.append(out.name)
        print(f"[webui] wrote {out.name}")

    all_hpp = OUT_DIR / "all_gen.hpp"
    includes = "\n".join(f'#include "{name}"' for name in sorted(generated))
    aggregate = f"/* auto-generated aggregator */\n#pragma once\n{includes}\n"
    all_hpp.write_text(aggregate, encoding="utf-8")
    print(f"[webui] wrote {all_hpp.name}")

    print("[webui] convert_html_in_code.py: DONE")
    print(f"[webui] Generated {len(generated)} headers in {OUT_DIR}")


def append_include_path_for_platformio() -> None:
    try:
        from SCons.Script import Import  # type: ignore

        Import("env")
        env.Append(CPPPATH=[str(OUT_DIR)])  # type: ignore[name-defined]
    except Exception:
        pass


if __name__ == "__main__":
    run()
else:
    run()
    append_include_path_for_platformio()
