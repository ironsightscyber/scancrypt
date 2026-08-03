"""The progress bar must agree with the label beside it.

A finished scan used to read "Done: 100.0%" next to an empty 0% bar, because the end-of-job
handler reset the bar's value. Side by side that reads as a scan that silently failed -- and
this is the first screen anyone sees, since the desktop app is the primary download.

Driven with Qt's offscreen platform so it runs in CI with no display attached.
"""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Skip on QtWidgets, not on PySide6. The top-level package imports fine on a bare Linux
# runner; QtWidgets is what pulls in libEGL, which GitHub's ubuntu images do not ship, so
# checking the wrong one let these fail at fixture setup instead of skipping. The desktop app
# ships on Windows and macOS, so covering it there is the point -- Linux would need extra
# system packages for no benefit to what we release.
pytest.importorskip("PySide6.QtWidgets",
                    reason="PySide6.QtWidgets unavailable (no Qt platform libraries here)")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    from rprt import gui
    w = gui.MainWindow()
    yield w
    w.close()


def test_finished_job_leaves_the_bar_agreeing_with_the_label(window):
    window._set_busy(True)
    for frac, label in [(0.25, "Coarse scan"), (0.75, "Refining boundary"), (1.0, "Done")]:
        window._on_progress(frac, label)
    window._set_busy(False)

    assert window.progress_bar.value() == window.progress_bar.maximum()
    assert "100.0%" in window.progress_label.text()


def test_cancelled_job_leaves_the_bar_where_it_stopped(window):
    """Neither end of the bar is honest after a cancel -- 0% implies nothing happened and
    100% implies it finished."""
    window._set_busy(True)
    window._on_progress(0.4, "Coarse scan")
    window._set_busy(False)

    assert window.progress_bar.value() == 400
    assert window.progress_bar.maximum() == 1000


def test_starting_a_job_returns_to_the_animated_state(window):
    """A new job must not inherit the previous one's fill, or the bar reads as already part
    done before anything has been measured."""
    window._set_busy(True)
    window._on_progress(1.0, "Done")
    window._set_busy(False)

    window._set_busy(True)

    assert window.progress_bar.maximum() == 0, "expected the indeterminate marquee"
    assert window.progress_label.text() == "Working…"


def test_phase_without_a_measurable_fraction_shows_no_bogus_percentage(window):
    """Locating a volume reports no fraction; it must not render as 0%."""
    window._set_busy(True)
    window._on_progress(0.0, "Finding the volume")

    assert window.progress_bar.maximum() == 0
    assert "%" not in window.progress_label.text()
    assert window.progress_label.text() == "Finding the volume"
