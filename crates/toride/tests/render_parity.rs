//! F01 base parity oracle: `TestBackend` buffer equality for the Dashboard
//! view.
//!
//! Invariant: rendering an UNCHANGED dashboard state twice must produce
//! identical terminal buffers. Any time-leak (shimmer phase, wall-clock
//! reads), hidden state mutation during render, or nondeterministic
//! iteration would make the second frame diverge from the first and fail
//! here. The optimization campaign's F01 parity oracles build on this
//! helper: a rendering change that preserves the buffer is behavior-neutral,
//! one that does not is a user-visible regression.
//!
//! The fixture and render helper are shared with the F01 bench via
//! `benches/common/mod.rs` so the oracle checks exactly what the bench
//! measures.

#[path = "../benches/common/mod.rs"]
mod common;

use common::{SIZES, fixed_dashboard, render_frame};
use ratatui::buffer::Buffer;

/// Render the same fixed dashboard state twice at each bench size and assert
/// the buffers are byte-identical (content AND styles), and that the frame
/// is non-degenerate (real chrome made it into the buffer — guards against a
/// silently blank render passing vacuously).
#[test]
fn unchanged_dashboard_state_renders_identical_buffers() {
    for (width, height) in SIZES {
        let mut screen = fixed_dashboard();

        let first: Buffer = render_frame(&mut screen, width, height);
        assert!(
            !first.area.is_empty(),
            "fixture frame at {width}x{height} must cover the terminal area"
        );
        let second: Buffer = render_frame(&mut screen, width, height);

        assert_eq!(
            first, second,
            "unchanged dashboard state rendered different buffers at {width}x{height}"
        );
    }
}

/// The fixed fixture must exercise the live-render path (collected status,
/// not the cold-start sentinel), otherwise the oracle would only cover the
/// empty skeleton frame.
#[test]
fn fixture_renders_live_dashboard_content() {
    let mut screen = fixed_dashboard();
    let frame = render_frame(&mut screen, 200, 60);
    let text: String = frame
        .content
        .iter()
        .map(|cell| cell.symbol().to_string())
        .collect();
    for expected in ["toride", "MANAGED SERVICES", "TOP PROCESSES", "firefox"] {
        assert!(
            text.contains(expected),
            "live fixture frame must contain {expected:?} (got {text:?})"
        );
    }
    assert!(
        !text.contains("collecting system status"),
        "fixture must not render the cold-start sentinel"
    );
}
