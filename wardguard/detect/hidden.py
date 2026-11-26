"""Hidden channels slot extractor (Lakshya)."""
from wardguard.model import ParsedFile, Slot


def extract_hidden_slots(pf: ParsedFile) -> None:
    """Extract slots from hidden channels: filename, headers, metadata."""
    if pf.status != "pending":
        return

    # Add @filename slot
    stem = pf.rel.split("/")[-1]
    pf.file_slots.append(
        Slot(
            path="@filename",
            text=stem,
            channel="filename",
            value_type="str",
        )
    )

    # Add headers if csv/tsv
    if pf.header:
        for idx, h in enumerate(pf.header):
            pf.file_slots.append(
                Slot(
                    path=f"@header:{idx}",
                    text=h,
                    channel="header",
                    value_type="str",
                )
            )
