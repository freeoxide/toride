use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

// ---------------------------------------------------------------------------
// TransitionParams — animated gradient parameters derived deterministically
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct TransitionParams {
    /// Direction to shift gradient center (fraction of area).
    pub center_offset: (f64, f64),
    /// Edge darkness modulation (negative = darken).
    pub edge_delta: f64,
    /// Midpoint dimming (negative = dimmer).
    pub brightness_dip: f64,
}

/// Deterministically derive transition parameters from a seed using bit
/// manipulation (no RNG crate).
pub fn params_from_seed(seed: u32) -> TransitionParams {
    // --- center_offset -------------------------------------------------------
    // Mix bits so that similar seeds produce very different angles.
    let angle_bits = (seed.wrapping_mul(0x045d_9f3b))
        .wrapping_add(0x9e37_79b9)
        .rotate_left(17);
    // Map to 0..2*PI using the high bits for best uniformity.
    let angle = (f64::from(angle_bits) / f64::from(u32::MAX)) * std::f64::consts::TAU;

    // Magnitude in 0.02..0.08 — noticeable but not extreme.
    let mag_bits = seed.wrapping_mul(0x01f1_d4f7).rotate_right(11);
    let magnitude = 0.02 + 0.06 * (f64::from(mag_bits) / f64::from(u32::MAX));

    let center_offset = (magnitude * angle.cos(), magnitude * angle.sin());

    // --- edge_delta ----------------------------------------------------------
    // Range -0.1 .. -0.2
    let edge_bits = seed.wrapping_mul(0x85eb_ca6b).rotate_left(7);
    let edge_delta = -0.1 - 0.1 * (f64::from(edge_bits) / f64::from(u32::MAX));

    // --- brightness_dip ------------------------------------------------------
    // Range -0.03 .. -0.1
    let dip_bits = seed.wrapping_mul(0xc2b2_ae35).rotate_right(5);
    let brightness_dip = -0.03 - 0.07 * (f64::from(dip_bits) / f64::from(u32::MAX));

    TransitionParams {
        center_offset,
        edge_delta,
        brightness_dip,
    }
}

// ---------------------------------------------------------------------------
// TransitionCache — caches seeds per navigation edge
// ---------------------------------------------------------------------------

pub type ScreenKey = u8;

/// Prime constant used to generate successive seeds.
const SEED_PRIME: u32 = 2_654_435_761;

pub struct TransitionCache {
    seeds: HashMap<(ScreenKey, ScreenKey), u32>,
    next_seed: u32,
}

impl Default for TransitionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TransitionCache {
    /// Create a new cache seeded from the current system time (nanos).
    pub fn new() -> Self {
        let base_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());

        // Spread the nanos out so nearby timestamps diverge.
        let next_seed = base_nanos
            .wrapping_mul(0x6c07_8965)
            .wrapping_add(1); // ensure non-zero

        TransitionCache {
            seeds: HashMap::new(),
            next_seed,
        }
    }

    /// Return the cached seed for `(from, to)`, creating one lazily if needed.
    ///
    /// The reverse path `(to, from)` reuses the **same** seed so forward and
    /// back navigation share a gradient.
    pub fn get_or_create_seed(&mut self, from: ScreenKey, to: ScreenKey) -> u32 {
        // Normalise the key so (a,b) and (b,a) map to the same entry.
        let key = if from <= to {
            (from, to)
        } else {
            (to, from)
        };

        if let Some(&seed) = self.seeds.get(&key) {
            return seed;
        }

        let seed = self.next_seed;
        self.next_seed = self.next_seed.wrapping_add(SEED_PRIME);
        self.seeds.insert(key, seed);
        seed
    }
}

// ---------------------------------------------------------------------------
// TransitionState — live transition between two screens
// ---------------------------------------------------------------------------

/// Default transition duration (400 ms).
const DEFAULT_DURATION: Duration = Duration::from_millis(400);

pub struct TransitionState {
    pub from: ScreenKey,
    pub to: ScreenKey,
    pub start: Instant,
    pub duration: Duration,
    pub params: TransitionParams,
    /// `true` when navigating backwards (e.g. Escape / Back).
    pub reverse: bool,
}

impl TransitionState {
    /// Create a new transition, pulling (or generating) the seed from `cache`.
    pub fn new(
        from: ScreenKey,
        to: ScreenKey,
        cache: &mut TransitionCache,
        reverse: bool,
    ) -> Self {
        let seed = cache.get_or_create_seed(from, to);
        let params = params_from_seed(seed);

        TransitionState {
            from,
            to,
            start: Instant::now(),
            duration: DEFAULT_DURATION,
            params,
            reverse,
        }
    }

    /// Raw progress in `0.0 .. 1.0`, clamped.
    pub fn progress(&self) -> f32 {
        let elapsed = self.start.elapsed().as_secs_f32();
        let total = self.duration.as_secs_f32();
        (elapsed / total).clamp(0.0, 1.0)
    }

    /// Whether the transition has completed.
    pub fn is_done(&self) -> bool {
        self.progress() >= 1.0
    }
}
