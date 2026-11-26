"""Unit and Slot enumeration for records."""
from wardguard.model import ParsedFile, Slot, Unit


def enumerate_units(pf: ParsedFile) -> None:
    """Enumerate units and slots from a parsed file."""
    if pf.status != "pending":
        return

    if pf.fmt in ("csv", "tsv") and pf.rows is not None and pf.header is not None:
        for idx, row in enumerate(pf.rows):
            loc = f"row:{idx}"
            unit = Unit(
                uid=f"{pf.rel}#{loc}",
                file_rel=pf.rel,
                loc=loc,
            )
            for c_idx, val in enumerate(row):
                hdr = pf.header[c_idx] if c_idx < len(pf.header) and pf.header[c_idx] else f"#{c_idx}"
                slot = Slot(
                    path=f"col:{hdr}",
                    text=val,
                    channel="content",
                    value_type="str",
                )
                unit.slots.append(slot)
            pf.units.append(unit)

    elif pf.fmt in ("json", "fhir") and pf.obj is not None:
        # If obj is a list of dicts, treat each element as a unit
        if isinstance(pf.obj, list):
            for idx, item in enumerate(pf.obj):
                loc = f"/{idx}"
                unit = Unit(
                    uid=f"{pf.rel}#{loc}",
                    file_rel=pf.rel,
                    loc=loc,
                )
                if isinstance(item, dict):
                    for k, v in item.items():
                        unit.slots.append(
                            Slot(
                                path=f"/{idx}/{k}",
                                text=str(v) if v is not None else "",
                                channel="content",
                                value_type="str" if isinstance(v, str) else "int" if isinstance(v, int) else "float" if isinstance(v, float) else "bool" if isinstance(v, bool) else "null",
                            )
                        )
                pf.units.append(unit)
        else:
            loc = "doc"
            unit = Unit(
                uid=f"{pf.rel}#{loc}",
                file_rel=pf.rel,
                loc=loc,
            )
            if isinstance(pf.obj, dict):
                for k, v in pf.obj.items():
                    unit.slots.append(
                        Slot(
                            path=f"/{k}",
                            text=str(v) if v is not None else "",
                            channel="content",
                            value_type="str" if isinstance(v, str) else "int" if isinstance(v, int) else "float" if isinstance(v, float) else "bool" if isinstance(v, bool) else "null",
                        )
                    )
            pf.units.append(unit)
    elif pf.fmt == "text" and pf.text is not None:
        loc = "doc"
        unit = Unit(
            uid=f"{pf.rel}#{loc}",
            file_rel=pf.rel,
            loc=loc,
        )
        unit.slots.append(
            Slot(
                path="doc",
                text=pf.text,
                channel="content",
                value_type="str",
            )
        )
        pf.units.append(unit)
