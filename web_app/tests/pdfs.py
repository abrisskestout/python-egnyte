"""Small real PDFs for the tests: built here, so no binary files are kept in the repository."""
import io

from pypdf import PdfWriter


def _escape(text):
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_pdf(*pages):
    """A valid PDF with one line of text (a real text layer) on each page. Pass the line for each page."""
    objects = {}                                    # object number -> body
    page_numbers = []
    next_number = 4                                 # 1 catalog, 2 page tree, 3 font
    for line in pages:
        content = f"BT /F1 12 Tf 72 720 Td ({_escape(line)}) Tj ET".encode("latin-1")
        stream = b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"
        page = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {next_number + 1} 0 R "
                f"/Resources << /Font << /F1 3 0 R >> >> >>").encode()
        objects[next_number], objects[next_number + 1] = page, stream
        page_numbers.append(next_number)
        next_number += 2
    kids = " ".join(f"{n} 0 R" for n in page_numbers)
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_numbers)} >>".encode()
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = {}
    for number in sorted(objects):
        offsets[number] = out.tell()
        out.write(b"%d 0 obj\n" % number + objects[number] + b"\nendobj\n")
    xref_at = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for number in sorted(objects):
        out.write(b"%010d 00000 n \n" % offsets[number])
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref_at))
    return out.getvalue()


def blank_pdf(pages=1):
    """A PDF whose pages have no text at all: what a scan looks like to a text extractor (here, an empty page)."""
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=612, height=792)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def locked_pdf(*pages, user_password="secret"):
    """A text PDF that needs a password to open."""
    return _encrypted(text_pdf(*pages), user_password)


def restricted_pdf(*pages):
    """A text PDF with an owner password only: anyone can open and read it (it just restricts editing)."""
    return _encrypted(text_pdf(*pages), "", owner_password="owner-secret")


def _encrypted(data, user_password, owner_password=None):
    from pypdf import PdfReader
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(data)))
    writer.encrypt(user_password=user_password, owner_password=owner_password or user_password, algorithm="AES-128")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
