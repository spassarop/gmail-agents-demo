from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Tuple


class RuntimeLoadError(RuntimeError):
    pass


def _purge_package(alias: str) -> None:
    for name in list(sys.modules.keys()):
        if name == alias or name.startswith(f"{alias}."):
            sys.modules.pop(name, None)


def load_package_alias(alias: str, package_dir: str | Path, *, reload: bool = False) -> ModuleType:
    package_path = Path(package_dir).resolve()
    init_py = package_path / "__init__.py"
    if not init_py.exists():
        raise RuntimeLoadError(f"Missing package __init__.py for {alias}: {init_py}")

    if reload:
        _purge_package(alias)

    existing = sys.modules.get(alias)
    if existing is not None:
        return existing

    spec = importlib.util.spec_from_file_location(
        alias,
        init_py,
        submodule_search_locations=[str(package_path)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeLoadError(f"Could not create import spec for {alias} from {package_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def import_runtime_submodule(alias: str, package_dir: str | Path, submodule: str, *, reload: bool = False):
    load_package_alias(alias, package_dir, reload=reload)
    return importlib.import_module(f"{alias}.{submodule}")


def runtime_package_info(mode: str, repo_root: str | Path) -> Tuple[str, Path]:
    repo_root = Path(repo_root).resolve()
    if mode == "vuln":
        return "testing_runtime_vuln", repo_root / "agentic_mailer"
    if mode == "patched":
        return "testing_runtime_patched", repo_root / "patched" / "agentic_mailer"
    raise RuntimeLoadError(f"Unknown runtime mode: {mode}")


def load_runtime_package(mode: str, repo_root: str | Path, *, reload: bool = False) -> ModuleType:
    alias, package_dir = runtime_package_info(mode, repo_root)
    return load_package_alias(alias, package_dir, reload=reload)
