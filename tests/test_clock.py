from datetime import datetime, timezone
from src.clock import apply_offset, infer_offset_seconds


def test_apply_offset_corrects_time_forward_running_clock():
    raw_time = datetime(2026, 7, 13, 9, 5, 0, tzinfo=timezone.utc)
    corrected = apply_offset(raw_time, -3900)
    expected = datetime(2026, 7, 13, 8, 0, 0, tzinfo=timezone.utc)
    assert corrected == expected


def test_apply_offset_corrects_time_backward_running_clock():
    raw_time = datetime(2026, 7, 13, 8, 0, 0, tzinfo=timezone.utc)
    corrected = apply_offset(raw_time, 3900)
    expected = datetime(2026, 7, 13, 9, 5, 0, tzinfo=timezone.utc)
    assert corrected == expected


def test_apply_offset_zero_does_nothing():
    raw_time = datetime(2026, 7, 13, 8, 0, 0, tzinfo=timezone.utc)
    corrected = apply_offset(raw_time, 0)
    assert corrected == raw_time


def test_infer_offset_from_two_anchor_times():
    anchor_a = datetime(2026, 7, 13, 8, 0, 0, tzinfo=timezone.utc)   # trusted/reference time
    anchor_b = datetime(2026, 7, 13, 9, 5, 0, tzinfo=timezone.utc)   # same real moment, endpoint's clock
    offset = infer_offset_seconds(anchor_a, anchor_b)
    assert offset == -3900
