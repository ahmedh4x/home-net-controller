"""
NetCutter Main Entrypoint.
Launches the modern PySide6 Desktop GUI by default, or runs CLI commands when arguments are provided.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def run_gui():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        raise SystemExit(
            "NetCutter's desktop GUI requires PySide6. "
            "Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    from netcutter.ui_qt.app_window import NetCutterMainWindow
    from netcutter.ui_qt.theme import Theme

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("NetCutter")
    app.setStyleSheet(Theme.get_stylesheet())
    window = NetCutterMainWindow()
    window.show()
    sys.exit(app.exec())


def run_legacy_tk():
    import tkinter as tk
    from netcutter.ui.app import NetCutterApp

    root = tk.Tk()
    app = NetCutterApp(root)
    root.mainloop()


def run_cli():
    from netcutter.cli.main import main
    main()


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.AttachConsole(-1)
        except Exception:
            pass

    is_cli_binary = "cli" in Path(sys.argv[0]).stem.lower()
    if len(sys.argv) > 1 and sys.argv[1] == "--legacy-tk":
        run_legacy_tk()
    elif is_cli_binary:
        run_cli()
    elif len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        run_cli()
    else:
        run_gui()
