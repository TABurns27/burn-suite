"""Shared helper for loading Burn Suite tools as importable modules in tests.

The tools are standalone scripts (by design — each one is meant to be
copied and run on its own), so they aren't a normal importable package.
This loads a tool by path via importlib instead.
"""
import os
import importlib.util

SUITE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    """Import a Burn Suite tool script (e.g. 'burnscanner') by name.

    Each call returns a fresh module instance, so tests don't leak
    module-level state (DIAGNOSTICS, CVE_CACHE, etc.) between each other.
    """
    path = os.path.join(SUITE_DIR, f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_file(path):
    """Read a generated report file with its handle properly closed."""
    with open(path, encoding='utf-8') as f:
        return f.read()
