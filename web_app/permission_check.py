"""The permission comparison: three actions on one file, run as whoever is signed in.

Every call here goes through the signed-in user's own Egnyte token, so Egnyte decides what that person may
do. Two people pressing the same button can get different answers; that difference is what this section shows.

The folder comes from configuration (the PERMISSION_TEST_FOLDER app setting, see settings.py) and the file name from
the constants below. Neither is ever taken from a request, so there is nothing to inject.
"""
import io

import egnyte_access  # noqa: F401  (puts the egnyte package on the import path; must come before the next line)
from egnyte import exc

FILE_BASENAME = "Text Test"        # an existing "Text Test" or "Text Test.txt" (any capitals) is the file
CREATE_AS = "Text Test.txt"        # what the Create button names a new file
MAX_EDIT_BYTES = 1024 * 1024       # larger files are not read or edited here
PREVIEW_CHARS = 2000


class ActionRefused(Exception):
    """The action can't be done because of the state of the folder (not because Egnyte refused this user).
    The message is safe to show."""


def file_path(folder, name):
    return f"{folder}/{name}"


def name_of(item):
    # vars() avoids the library's lazy per-item fetch (one API call each)
    return vars(item).get("name") or item.path.rsplit("/", 1)[-1]


def find_file(listing):
    """(entry, name) for the Text Test file in a folder listing, or (None, None)."""
    wanted = {FILE_BASENAME.lower(), FILE_BASENAME.lower() + ".txt"}
    for item in listing.files:
        name = name_of(item)
        if name.lower() in wanted:
            return item, name
    return None, None


def read_all(client, path):
    buffer = io.BytesIO()
    client.file(path).download().write_to(buffer)
    return buffer.getvalue()


def _find(client, folder):
    """(entry, name) of the file in the folder, or (None, None) if it isn't there. Raises ActionRefused if the
    folder itself can't be found; Egnyte's 'not allowed' passes through for the caller to report."""
    try:
        listing = client.folder(folder).list()
    except exc.NotFound:
        raise ActionRefused(f"The folder {folder} does not exist, or your Egnyte account can't see it.") from None
    if getattr(listing, "folders", None) is None:
        raise ActionRefused(f"{folder} is not a folder.")
    return find_file(listing)


# --------------------------------------------------------------------------- what is there now

def inspect(client, folder):
    """The current state as this user sees it. Never raises for 'not allowed' or 'not there': it reports them."""
    state = {"folder": folder, "folder_status": "ok", "file": None, "preview": None, "preview_note": None}
    try:
        listing = client.folder(folder).list()
    except exc.InsufficientPermissions:
        state["folder_status"] = "denied"
        return state
    except exc.NotFound:
        state["folder_status"] = "missing"
        return state
    if getattr(listing, "folders", None) is None:
        state["folder_status"] = "not_a_folder"
        return state

    entry, name = find_file(listing)
    if entry is None:
        return state
    meta = vars(entry)
    state["file"] = {"name": name, "size": meta.get("size"), "modified": meta.get("last_modified"),
                     "modified_by": meta.get("uploaded_by")}
    if (meta.get("size") or 0) > MAX_EDIT_BYTES:
        state["preview_note"] = "The file is too large to show or edit here."
        return state
    try:
        data = read_all(client, entry.path)
    except exc.InsufficientPermissions:
        state["preview_note"] = "Your Egnyte account can list this folder but is not allowed to read the file."
    except exc.NotFound:
        state["preview_note"] = "The file was removed while this page loaded."
    else:
        state["preview"] = data.decode("utf-8", "replace")[:PREVIEW_CHARS]
    return state


# --------------------------------------------------------------------------- the three actions

def edit(client, folder, who):
    """Add the line 'edited by <who>' to the end of the file. Returns the file's name."""
    entry, name = _find(client, folder)
    if entry is None:
        raise ActionRefused(f"{FILE_BASENAME} does not exist yet. Use Create file first.")
    if (vars(entry).get("size") or 0) > MAX_EDIT_BYTES:
        raise ActionRefused(f"{name} is too large to edit here.")
    data = read_all(client, entry.path)
    if len(data) > MAX_EDIT_BYTES:
        raise ActionRefused(f"{name} is too large to edit here.")
    separator = b"" if not data or data.endswith(b"\n") else b"\n"
    client.file(entry.path).upload(data + separator + f"edited by {who}\n".encode("utf-8"))
    return name


def create(client, folder, who):
    """Create the file if it doesn't exist. Returns the new file's name."""
    entry, name = _find(client, folder)
    if entry is not None:
        raise ActionRefused(f"{name} already exists, so nothing was changed.")
    client.file(file_path(folder, CREATE_AS)).upload(f"created by {who}\n".encode("utf-8"))
    return CREATE_AS


def delete(client, folder):
    """Delete the file. Returns the deleted file's name."""
    entry, name = _find(client, folder)
    if entry is None:
        raise ActionRefused(f"{FILE_BASENAME} does not exist, so there is nothing to delete.")
    client.file(entry.path).delete()
    return name
