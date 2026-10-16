"""
NetCutter Main Entrypoint.
Launches the modern PySide6 Desktop GUI by default, or runs CLI commands when arguments are provided.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def check_platform():
    """Warn if running on non-Windows operating systems."""
    if sys.platform != "win32":
        sys.stderr.write(
            "Notice: Home Net Controller (HNC) is officially developed and supported exclusively "
            "on Microsoft Windows (Windows 10 / 11 x64).\n"
            f"Detected platform: {sys.platform}. Core Windows subsystems (DPAPI credential protection, "
            "Npcap raw packet capture, and Windows LAN off-path interceptor) require Windows.\n"
        )


def run_gui():
    check_platform()
    try:
        from netcutter.ui_qt import run_gui as _run_gui
    except ImportError as exc:
        raise SystemExit(
            "Home Net Controller desktop GUI requires PySide6. "
            "Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    sys.exit(_run_gui())



def run_cli():
    check_platform()
    from netcutter.cli.main import main
    main()


if __name__ == "__main__":
    check_platform()
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.AttachConsole(-1)
        except Exception:
            pass

    is_cli_binary = "cli" in Path(sys.argv[0]).stem.lower()
    if is_cli_binary:
        run_cli()
    elif len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        run_cli()
    else:
        run_gui()
