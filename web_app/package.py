#!/usr/bin/env python
"""Build the deployment package: dist/egnyte-webapp.zip.

The zip holds the web app, the vendored egnyte/ library folder from this checkout (without its tests and
CLI) and LICENSE.txt, laid out so that `egnyte` imports from next to the app. That is how it is meant to be
deployed: pip would install the 2017 release from PyPI, which is not what you tested.

Only files on an explicit list go in, so nothing else in this folder (stored tokens, .env files, tests,
caches) can end up in a package by accident.

    python web_app/package.py            # writes web_app/dist/egnyte-webapp.zip
    python web_app/package.py --list     # also prints every file in the package
"""
import argparse
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

APP_FILES = ("app.py", "wsgi.py", "settings.py", "identity.py", "egnyte_oauth.py", "token_store.py",
             "egnyte_access.py", "requirements.txt")
APP_DIRS = ("templates", "static")
LIBRARY_DIR = "egnyte"
LIBRARY_SKIP_DIRS = {"tests", "__pycache__"}
LIBRARY_SKIP_FILES = {"__main__.py"}     # the command-line tool; the web app doesn't use it
LICENSE = "LICENSE.txt"
# Tells App Service's build (Oryx) to install requirements.txt when the zip is deployed.
DEPLOYMENT_FILE = b"[config]\nSCM_DO_BUILD_DURING_DEPLOYMENT=true\n"
DEFAULT_OUTPUT = os.path.join(HERE, "dist", "egnyte-webapp.zip")


class PackageError(Exception):
    pass


def _walk(root, skip_dirs=(), skip_files=(), keep=lambda name: True):
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        for name in sorted(files):
            if name not in skip_files and not name.endswith((".pyc", ".pyo")) and keep(name):
                yield os.path.join(folder, name)


def collect(app_dir=HERE, repo_dir=REPO):
    """The (path on disk, name inside the zip) pairs that make up the package."""
    entries = []
    for name in APP_FILES:
        path = os.path.join(app_dir, name)
        if not os.path.isfile(path):
            raise PackageError(f"missing {path}")
        entries.append((path, name))
    for folder in APP_DIRS:
        root = os.path.join(app_dir, folder)
        if not os.path.isdir(root):
            raise PackageError(f"missing folder {root}")
        entries += [(p, os.path.relpath(p, app_dir)) for p in _walk(root, skip_dirs={"__pycache__"})]
    library = os.path.join(repo_dir, LIBRARY_DIR)
    if not os.path.isfile(os.path.join(library, "__init__.py")):
        raise PackageError(f"the egnyte library folder was not found at {library}")
    entries += [(p, os.path.relpath(p, repo_dir)) for p in _walk(library, LIBRARY_SKIP_DIRS, LIBRARY_SKIP_FILES)]
    license_path = os.path.join(repo_dir, LICENSE)
    if not os.path.isfile(license_path):
        raise PackageError(f"missing {license_path}; the library's license has to travel with it")
    entries.append((license_path, LICENSE))
    return [(path, name.replace(os.sep, "/")) for path, name in entries]


def build(output=DEFAULT_OUTPUT, app_dir=HERE, repo_dir=REPO):
    entries = collect(app_dir, repo_dir)
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(".deployment", DEPLOYMENT_FILE)
        for path, name in entries:
            archive.write(path, name)
    return output, [".deployment"] + [name for _, name in entries]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the web app deployment package.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="where to write the zip")
    parser.add_argument("--list", action="store_true", help="print every file in the package")
    args = parser.parse_args(argv)
    try:
        output, names = build(args.output)
    except PackageError as e:
        print(f"Cannot build the package: {e}")
        return 1
    if args.list:
        print("\n".join(names))
    print(f"Wrote {output} ({os.path.getsize(output) / 1024:.0f} KB, {len(names)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
