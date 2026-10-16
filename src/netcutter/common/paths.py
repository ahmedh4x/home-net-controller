"""Portable, writable application-data locations for NetCutter."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def get_app_data_dir() -> Path:
    """Return a writable per-user data directory, creating it when possible.

    ``NETCUTTER_DATA_DIR`` is intentionally supported for tests and managed
    deployments. Windows uses LOCALAPPDATA first; older installations using
    ``~/.netcutter`` remain a fallback for compatibility.
    """
    override = os.environ.get("HNC_DATA_DIR") or os.environ.get("NETCUTTER_DATA_DIR")
    candidates = []
    if override:
        candidates.append(Path(override))
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(Path(local_app_data) / "HomeNetController")
            candidates.append(Path(local_app_data) / "NetCutter")
    candidates.append(Path.home() / ".hnc")
    candidates.append(Path.home() / ".netcutter")
    candidates.append(Path(tempfile.gettempdir()) / "HomeNetController")

    last_error: OSError | None = None
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # A write probe catches directories that exist but are ACL-denied.
            probe = candidate / ".write-probe"
            probe.touch(exist_ok=False)
            probe.unlink()
            return candidate
        except OSError as exc:
            last_error = exc

    raise OSError("No writable NetCutter application-data directory found") from last_error


def get_assets_dir() -> Path:
    """Return the absolute Path to the assets directory.

    Works seamlessly in development, pytest, and frozen PyInstaller bundles
    (both onedir under _internal/assets or assets, and onefile under sys._MEIPASS).
    """
    import sys

    # 1. PyInstaller frozen onefile/onedir sys._MEIPASS
    if hasattr(sys, "_MEIPASS"):
        meipass_assets = Path(sys._MEIPASS) / "assets"
        if meipass_assets.is_dir():
            return meipass_assets
        # If sys._MEIPASS directly contains icons/
        if (Path(sys._MEIPASS) / "icons").is_dir():
            return Path(sys._MEIPASS)

    # 2. PyInstaller frozen onedir: _internal/assets or sibling assets/
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).parent
        internal_assets = exe_dir / "_internal" / "assets"
        if internal_assets.is_dir():
            return internal_assets
        sibling_assets = exe_dir / "assets"
        if sibling_assets.is_dir():
            return sibling_assets

    # 3. Development / source layout: 3 levels up from paths.py (src/netcutter/common -> root)
    repo_assets = Path(__file__).resolve().parents[3] / "assets"
    if repo_assets.is_dir():
        return repo_assets

    # 4. Fallback: check current working directory
    cwd_assets = Path.cwd() / "assets"
    if cwd_assets.is_dir():
        return cwd_assets

    return repo_assets


def get_asset_path(relative_path: str = "") -> Path:
    """Return the absolute Path to a specific asset file or folder."""
    base = get_assets_dir()
    if not relative_path:
        return base
    return base / relative_path
