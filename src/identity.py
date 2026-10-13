def canonicalize_identity(raw: str) -> str:
    raw = raw.strip().lower()
    if "@" in raw:
        return raw.split("@")[0]
    if "\\" in raw:
        return raw.split("\\")[-1]
    return raw
