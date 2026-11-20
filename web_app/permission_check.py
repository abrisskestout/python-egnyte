"""The permission comparison: three actions on one file, run as whoever is signed in, plus reading the text layer of
the PDFs in the same folder.

Every call here goes through the signed-in user's own Egnyte token, so Egnyte decides what that person may
do. Two people pressing the same button can get different answers; that difference is what this section shows.

The folder comes from configuration (the PERMISSION_TEST_FOLDER app setting, see settings.py) and the file name from
the constants below. Neither is ever taken from a request, so there is nothing to inject. The one exception is the
PDF button, which sends a file name: it is only ever compared with the names in the folder's live listing, and the
path that is downloaded is the one Egnyte listed, never one built from the request.
"""
import io
import logging
import re

import egnyte_access  # noqa: F401  (puts the egnyte package on the import path; must come before the next line)
from egnyte import exc
from pypdf import PdfReader

log = logging.getLogger("egnyte.permissions")

FILE_BASENAME = "Text Test"        # an existing "Text Test" or "Text Test.txt" (any capitals) is the file
CREATE_AS = "Text Test.txt"        # what the Create button names a new file
MAX_EDIT_BYTES = 1024 * 1024       # larger files are not read or edited here
PREVIEW_CHARS = 2000

# Reading a PDF's text layer. The limits keep one click from tying up the site's single worker or filling a page.
PDF_SUFFIX = ".pdf"
MAX_PDF_BYTES = 10 * 1024 * 1024   # larger PDFs are not downloaded
MAX_PDF_PAGES = 50                 # pages after these are not read
MAX_PDF_TEXT_CHARS = 100_000       # text after this is cut off
MAX_PDF_BUTTONS = 25               # PDFs listed on the page
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")      # everything but tab and newline


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


def is_pdf(name):
    return name.lower().endswith(PDF_SUFFIX)


def find_pdfs(listing):
    """[(name, size)] of the PDFs in a folder listing, sorted by name."""
    pdfs = [(name_of(item), vars(item).get("size")) for item in listing.files if is_pdf(name_of(item))]
    return sorted(pdfs, key=lambda pdf: pdf[0].lower())


def _listing(client, folder):
    """The folder's listing. Raises ActionRefused if the folder itself can't be found; Egnyte's 'not allowed'
    passes through for the caller to report."""
    try:
        listing = client.folder(folder).list()
    except exc.NotFound:
        raise ActionRefused(f"The folder {folder} does not exist, or your Egnyte account can't see it.") from None
    if getattr(listing, "folders", None) is None:
        raise ActionRefused(f"{folder} is not a folder.")
    return listing


def _find(client, folder):
    """(entry, name) of the file in the folder, or (None, None) if it isn't there."""
    return find_file(_listing(client, folder))


# --------------------------------------------------------------------------- what is there now

def inspect(client, folder):
    """The current state as this user sees it. Never raises for 'not allowed' or 'not there': it reports them."""
    state = {"folder": folder, "folder_status": "ok", "file": None, "preview": None, "preview_note": None,
             "pdfs": [], "pdfs_hidden": 0}
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

    pdfs = find_pdfs(listing)
    state["pdfs"] = [{"name": name, "size": size} for name, size in pdfs[:MAX_PDF_BUTTONS]]
    state["pdfs_hidden"] = max(0, len(pdfs) - MAX_PDF_BUTTONS)

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


# --------------------------------------------------------------------------- the text layer of a PDF

def _clean(text):
    return _CONTROL_CHARS.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))


def extract_pdf_text(data):
    """The text layer of a PDF (the text already inside the file; no OCR), one '--- Page n ---' block per page.

    Returns {"pages", "pages_read", "pages_with_text", "text", "notes"}. Raises ActionRefused, with a message that is
    safe to show, if the file is password-protected or can't be parsed. The file is untrusted, so any failure inside
    the parser is reported that way instead of becoming an error page."""
    notes = []
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted and not reader.decrypt(""):     # a PDF that only restricts editing opens with ""
            raise ActionRefused("This PDF is password-protected, so its text can't be read here.")
        total = len(reader.pages)
        blocks, with_text, size, cut = [], 0, 0, False
        for number in range(min(total, MAX_PDF_PAGES)):
            text = _clean(reader.pages[number].extract_text() or "").strip()
            with_text += bool(text)
            blocks.append(f"--- Page {number + 1} ---\n{text}")
            size += len(blocks[-1]) + 2
            if size > MAX_PDF_TEXT_CHARS:
                cut = True
                break
    except ActionRefused:
        raise
    except Exception as e:       # noqa: BLE001 - a damaged or hostile file can make the parser fail in many ways
        log.warning("A PDF could not be read: %s", type(e).__name__)
        raise ActionRefused("This file could not be read as a PDF (it may be damaged).") from None

    read = len(blocks)
    text = "\n\n".join(blocks)[:MAX_PDF_TEXT_CHARS]
    if total == 0:
        notes.append("This PDF has no pages.")
    elif with_text == 0:
        notes.append("No text layer was found. This PDF is probably a scan (a picture of each page), "
                     "so getting its text needs OCR.")
    elif with_text < read:
        notes.append(f"{read - with_text} of the {read} pages read have no text layer (probably scans).")
    if cut:
        notes.append(f"The text was cut off after {MAX_PDF_TEXT_CHARS:,} characters, at page {read}.")
    elif read < total:
        notes.append(f"Only the first {read} of {total} pages were read.")
    return {"pages": total, "pages_read": read, "pages_with_text": with_text, "text": text, "notes": notes}


def pdf_text(client, folder, name):
    """Download one PDF from the folder, as this user, and return its text layer (see extract_pdf_text) with the
    file's "name" and "size". `name` comes from a request, so it only selects a file Egnyte listed in the folder;
    anything else is refused. Egnyte's 'not allowed' passes through for the caller to report."""
    listing = _listing(client, folder)
    entry = next((item for item in listing.files if is_pdf(name_of(item)) and name_of(item) == name), None)
    if entry is None:
        raise ActionRefused("That PDF is not in the folder (it may have been removed or renamed). Reload the page.")
    limit_mb = MAX_PDF_BYTES // (1024 * 1024)
    if (vars(entry).get("size") or 0) > MAX_PDF_BYTES:
        raise ActionRefused(f"{name} is too large to read here (the limit is {limit_mb} MB).")
    try:
        data = read_all(client, entry.path)
    except exc.NotFound:
        raise ActionRefused(f"{name} was removed while this page loaded.") from None
    if len(data) > MAX_PDF_BYTES:
        raise ActionRefused(f"{name} is too large to read here (the limit is {limit_mb} MB).")
    result = extract_pdf_text(data)
    result.update(name=name, size=len(data))
    return result
