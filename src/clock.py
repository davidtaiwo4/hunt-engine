from datetime import datetime, timedelta


def apply_offset(raw_time: datetime, offset_seconds: int) -> datetime:
    return raw_time + timedelta(seconds=offset_seconds)


def infer_offset_seconds(trusted_time: datetime, untrusted_time: datetime) -> int:
    delta = trusted_time - untrusted_time
    return int(delta.total_seconds())
