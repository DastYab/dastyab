//! Contextual Discounted UCB1 Multi-Armed Bandit, EWMA latency/jitter scoring,
//! 3-state Circuit Breaker, Hysteresis switching, and Happy Eyeballs v2
//! protocol-diverse slate selector.
//!
//! Pure, deterministic, dependency-free core shared conceptually with the
//! Android `AutopilotBrain` engine so desktop/daemon and mobile autopilots
//! make identical anti-flapping, exploration, and failover decisions.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Exponentially Weighted Moving Average smoothing factor for RTT & jitter.
pub const EWMA_ALPHA: f64 = 0.30;
/// Discount factor per decay tick so stale failures/wins fade gracefully.
pub const DISCOUNT_GAMMA: f64 = 0.90;
/// UCB1 exploration coefficient.
pub const UCB_EXPLORATION_C: f64 = 0.55;
/// Consecutive hard failures before tripping the circuit breaker `OPEN`.
pub const CIRCUIT_TRIP_FAILURES: u32 = 3;
/// Base quarantine window in seconds (exponentially backed off per trip).
pub const CIRCUIT_BASE_COOLDOWN_SECS: u64 = 30;
/// Ceiling quarantine window in seconds (30 minutes).
pub const CIRCUIT_MAX_COOLDOWN_SECS: u64 = 1800;
/// Hysteresis multiplier: a healthy active arm is only preempted when a
/// challenger outperforms it by >= 25% (`1.25x`) across multiple ticks.
pub const HYSTERESIS_PREEMPT_RATIO: f64 = 1.25;

/// User intent shaping acceptance gates & scoring preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AutopilotIntent {
    #[default]
    BalancedWeb,
    AiStudio,
    GoogleFlow,
    BlackoutSurvival,
}

/// Circuit breaker state for a single route/config arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CircuitState {
    #[default]
    Closed,
    Open {
        quarantine_until_unix: u64,
        trip_count: u32,
    },
    HalfOpen,
}

/// Geo-clearance bitmask constants (`arm.geo_mask`).
pub const GEO_CLEAR_WEB: u8 = 1 << 0;
pub const GEO_CLEAR_AISTUDIO: u8 = 1 << 1;
pub const GEO_CLEAR_FLOW: u8 = 1 << 2;

/// Candidate metadata supplied to the bandit selector.
#[derive(Debug, Clone)]
pub struct CandidateArm {
    pub arm_id: String,
    pub protocol_family: String,
    pub base_priority: f64,
}

/// Persisted telemetry for one arm under a specific network context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmStats {
    pub arm_id: String,
    pub protocol_family: String,
    pub ewma_ms: f64,
    pub jitter_ms: f64,
    pub discounted_wins: f64,
    pub discounted_trials: f64,
    pub consecutive_failures: u32,
    pub consecutive_wins: u32,
    pub circuit: CircuitState,
    pub geo_mask: u8,
    pub last_updated_unix: u64,
}

impl ArmStats {
    pub fn new(
        arm_id: impl Into<String>,
        protocol_family: impl Into<String>,
        now_unix: u64,
    ) -> Self {
        Self {
            arm_id: arm_id.into(),
            protocol_family: protocol_family.into(),
            ewma_ms: 0.0,
            jitter_ms: 0.0,
            discounted_wins: 1.0, // Beta(1,1) optimistic neutral prior
            discounted_trials: 2.0,
            consecutive_failures: 0,
            consecutive_wins: 0,
            circuit: CircuitState::Closed,
            geo_mask: 0,
            last_updated_unix: now_unix,
        }
    }

    pub fn survival_rate(&self) -> f64 {
        if self.discounted_trials <= 0.0 {
            return 0.5;
        }
        (self.discounted_wins / self.discounted_trials).clamp(0.0, 1.0)
    }

    /// Evaluate effective circuit state at `now_unix`, automatically promoting
    /// expired `Open` breakers to `HalfOpen`.
    pub fn effective_circuit(&self, now_unix: u64) -> CircuitState {
        match self.circuit {
            CircuitState::Open {
                quarantine_until_unix,
                trip_count,
            } => {
                if now_unix >= quarantine_until_unix {
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Open {
                        quarantine_until_unix,
                        trip_count,
                    }
                }
            }
            other => other,
        }
    }
}

/// Contextual bandit store scoped by network fingerprint (`wifi:...`, `cell:...`, `default`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextualBanditStore {
    pub contexts: HashMap<String, HashMap<String, ArmStats>>,
    pub clean_ip_seeds: HashMap<String, Vec<String>>,
}

impl ContextualBanditStore {
    /// Compute Discounted UCB1 + EWMA latency/jitter + Intent alignment score.
    pub fn score_arm(
        &self,
        network_ctx: &str,
        candidate: &CandidateArm,
        intent: AutopilotIntent,
        now_unix: u64,
    ) -> f64 {
        let map = self.contexts.get(network_ctx);
        let total_trials: f64 = map
            .map(|m| m.values().map(|a| a.discounted_trials).sum::<f64>())
            .unwrap_or(2.0)
            .max(2.0);

        let stats = map.and_then(|m| m.get(&candidate.arm_id));
        let Some(st) = stats else {
            // Unexplored arm receives high optimistic exploration prior + protocol hint.
            let ucb_prior = UCB_EXPLORATION_C * total_trials.ln().max(1.0).sqrt();
            return 0.60 + ucb_prior.min(0.65) + candidate.base_priority * 0.15;
        };

        let eff = st.effective_circuit(now_unix);
        if matches!(eff, CircuitState::Open { .. }) {
            return -10.0;
        }

        let survival = st.survival_rate();
        let latency_penalty = if st.ewma_ms > 0.0 {
            ((st.ewma_ms + 0.5 * st.jitter_ms) / 2500.0).clamp(0.0, 0.55)
        } else {
            0.12
        };
        let explore =
            UCB_EXPLORATION_C * (total_trials.ln().max(1.0) / st.discounted_trials.max(1.0)).sqrt();

        let intent_bonus = match intent {
            AutopilotIntent::BalancedWeb => {
                if (st.geo_mask & GEO_CLEAR_WEB) != 0 {
                    0.12
                } else {
                    0.0
                }
            }
            AutopilotIntent::AiStudio => {
                if (st.geo_mask & GEO_CLEAR_AISTUDIO) != 0 {
                    0.30
                } else {
                    0.0
                }
            }
            AutopilotIntent::GoogleFlow => {
                if (st.geo_mask & GEO_CLEAR_FLOW) != 0 {
                    0.40
                } else {
                    0.0
                }
            }
            AutopilotIntent::BlackoutSurvival => {
                let pf = candidate.protocol_family.to_ascii_lowercase();
                if matches!(
                    pf.as_str(),
                    "doh" | "quic" | "hy2" | "hysteria2" | "openvpn" | "wireguard"
                ) {
                    0.22
                } else {
                    0.05
                }
            }
        };

        let half_open_penalty = if eff == CircuitState::HalfOpen {
            0.18
        } else {
            0.0
        };

        (survival - latency_penalty
            + explore.min(0.60)
            + intent_bonus
            + candidate.base_priority * 0.10
            - half_open_penalty)
            .max(0.0)
    }

    /// Record an observed probe or connection outcome for `arm_id` on `network_ctx`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_outcome(
        &mut self,
        network_ctx: &str,
        arm_id: &str,
        protocol_family: &str,
        success: bool,
        rtt_ms: Option<f64>,
        geo_mask_observed: u8,
        now_unix: u64,
    ) {
        let ctx_map = self.contexts.entry(network_ctx.to_string()).or_default();
        let entry = ctx_map
            .entry(arm_id.to_string())
            .or_insert_with(|| ArmStats::new(arm_id, protocol_family, now_unix));

        // Time-decay existing evidence before adding new observation.
        entry.discounted_wins *= DISCOUNT_GAMMA;
        entry.discounted_trials = (entry.discounted_trials * DISCOUNT_GAMMA).max(1.0);
        entry.discounted_trials += 1.0;
        entry.last_updated_unix = now_unix;

        if success {
            entry.discounted_wins += 1.0;
            entry.consecutive_failures = 0;
            entry.consecutive_wins = entry.consecutive_wins.saturating_add(1);
            entry.circuit = CircuitState::Closed;
            entry.geo_mask |= geo_mask_observed;

            if let Some(ms) = rtt_ms.filter(|m| *m > 0.0 && m.is_finite()) {
                if entry.ewma_ms <= 0.0 {
                    entry.ewma_ms = ms;
                    entry.jitter_ms = ms * 0.10;
                } else {
                    let diff = (ms - entry.ewma_ms).abs();
                    entry.ewma_ms = EWMA_ALPHA * ms + (1.0 - EWMA_ALPHA) * entry.ewma_ms;
                    entry.jitter_ms = EWMA_ALPHA * diff + (1.0 - EWMA_ALPHA) * entry.jitter_ms;
                }
            }
        } else {
            entry.consecutive_wins = 0;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            let prev_trips = match entry.circuit {
                CircuitState::Open { trip_count, .. } => trip_count,
                _ => 0,
            };
            let eff = entry.effective_circuit(now_unix);
            if eff == CircuitState::HalfOpen || entry.consecutive_failures >= CIRCUIT_TRIP_FAILURES
            {
                let trips = prev_trips.saturating_add(1).max(1);
                let shift = (trips - 1).min(6);
                let backoff = CIRCUIT_BASE_COOLDOWN_SECS
                    .saturating_mul(1u64 << shift)
                    .min(CIRCUIT_MAX_COOLDOWN_SECS);
                entry.circuit = CircuitState::Open {
                    quarantine_until_unix: now_unix.saturating_add(backoff),
                    trip_count: trips,
                };
            }
        }
    }

    /// Happy Eyeballs v2 protocol-diverse slate selection:
    /// Slot 1 gets highest-scoring arm overall; subsequent slots prioritize distinct
    /// protocol families (`XRAY`, `QUIC`, `WIREGUARD`, `OPENVPN`, `PROXY`, `DOH`)
    /// before filling remaining slots by score. Skips `Open` quarantined arms unless
    /// nothing else exists.
    pub fn select_diverse_slate(
        &self,
        network_ctx: &str,
        candidates: &[CandidateArm],
        intent: AutopilotIntent,
        max_slots: usize,
        now_unix: u64,
    ) -> Vec<CandidateArm> {
        if candidates.is_empty() || max_slots == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(f64, &CandidateArm)> = candidates
            .iter()
            .map(|c| (self.score_arm(network_ctx, c, intent, now_unix), c))
            .collect();
        scored.sort_by(|a, b| {
            let score_ord = b.0.total_cmp(&a.0);
            score_ord.then_with(|| a.1.arm_id.cmp(&b.1.arm_id))
        });

        // Prefer non-quarantined candidates when at least one exists.
        let eligible: Vec<(f64, &CandidateArm)> = if scored.iter().any(|(s, _)| *s >= 0.0) {
            scored.into_iter().filter(|(s, _)| *s >= 0.0).collect()
        } else {
            scored
        };

        let mut selected: Vec<CandidateArm> = Vec::with_capacity(max_slots);
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut seen_families: HashSet<String> = HashSet::new();

        // Always pick top overall arm first.
        if let Some((_, best)) = eligible.first() {
            selected.push((*best).clone());
            seen_ids.insert(best.arm_id.clone());
            seen_families.insert(best.protocol_family.to_ascii_lowercase());
        }

        // Next pass: pick best arm from each unseen protocol family.
        for (_, cand) in &eligible {
            if selected.len() >= max_slots {
                break;
            }
            let fam = cand.protocol_family.to_ascii_lowercase();
            if !seen_ids.contains(&cand.arm_id) && !seen_families.contains(&fam) {
                selected.push((*cand).clone());
                seen_ids.insert(cand.arm_id.clone());
                seen_families.insert(fam);
            }
        }

        // Final pass: fill any remaining slots by raw bandit score.
        for (_, cand) in eligible {
            if selected.len() >= max_slots {
                break;
            }
            if seen_ids.insert(cand.arm_id.clone()) {
                selected.push(cand.clone());
            }
        }

        selected
    }

    /// Remember a verified clean IP seed for `/24` neighborhood scouting on this network.
    pub fn record_clean_ip_seed(&mut self, network_ctx: &str, ip: &str) {
        let list = self
            .clean_ip_seeds
            .entry(network_ctx.to_string())
            .or_default();
        list.retain(|x| x != ip);
        list.insert(0, ip.to_string());
        if list.len() > 24 {
            list.truncate(24);
        }
    }
}

/// Anti-flapping Hysteresis guard: an active healthy arm is only replaced if
/// the challenger wins by `>= HYSTERESIS_PREEMPT_RATIO` across `>= 2` streaks,
/// or if the active route itself is degraded/unhealthy.
pub fn should_preempt_active(
    active_healthy: bool,
    active_score: f64,
    challenger_score: f64,
    challenger_lead_streak: u32,
) -> bool {
    if !active_healthy {
        return true;
    }
    if active_score <= 0.0 {
        return challenger_score > 0.0;
    }
    challenger_lead_streak >= 2 && challenger_score >= active_score * HYSTERESIS_PREEMPT_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, fam: &str) -> CandidateArm {
        CandidateArm {
            arm_id: id.to_string(),
            protocol_family: fam.to_string(),
            base_priority: 0.5,
        }
    }

    #[test]
    fn contextual_bandit_isolates_network_contexts_and_prefers_fast_reliable_arm() {
        let mut store = ContextualBanditStore::default();
        let net_a = "cell:432-35";
        let net_b = "wifi:home";

        for t in 1..=5 {
            store.record_outcome(
                net_a,
                "vless-1",
                "xray",
                true,
                Some(110.0),
                GEO_CLEAR_WEB | GEO_CLEAR_AISTUDIO,
                t,
            );
            store.record_outcome(
                net_a,
                "vless-2",
                "xray",
                true,
                Some(850.0),
                GEO_CLEAR_WEB,
                t,
            );
            store.record_outcome(net_b, "vless-2", "xray", true, Some(95.0), GEO_CLEAR_WEB, t);
        }

        let s1_a = store.score_arm(
            net_a,
            &cand("vless-1", "xray"),
            AutopilotIntent::AiStudio,
            10,
        );
        let s2_a = store.score_arm(
            net_a,
            &cand("vless-2", "xray"),
            AutopilotIntent::AiStudio,
            10,
        );
        assert!(
            s1_a > s2_a,
            "fast AI Studio clear arm must win on net_a: {s1_a} vs {s2_a}"
        );

        let s2_b = store.score_arm(
            net_b,
            &cand("vless-2", "xray"),
            AutopilotIntent::BalancedWeb,
            10,
        );
        assert!(
            s2_b > s2_a,
            "network context isolation must preserve net_b win"
        );
    }

    #[test]
    fn circuit_breaker_trips_quarantines_and_recovers_via_half_open() {
        let mut store = ContextualBanditStore::default();
        let net = "cell:432-11";
        let c = cand("bad-arm", "xray");

        // Three consecutive failures trip OPEN with 30s quarantine.
        store.record_outcome(net, "bad-arm", "xray", false, None, 0, 100);
        store.record_outcome(net, "bad-arm", "xray", false, None, 0, 101);
        store.record_outcome(net, "bad-arm", "xray", false, None, 0, 102);

        assert!(store.score_arm(net, &c, AutopilotIntent::BalancedWeb, 110) < 0.0);

        // At t=132 (30s later), circuit transitions to HALF_OPEN -> eligible for canary probe.
        assert!(store.score_arm(net, &c, AutopilotIntent::BalancedWeb, 132) >= 0.0);

        // If canary succeeds, circuit closes cleanly.
        store.record_outcome(
            net,
            "bad-arm",
            "xray",
            true,
            Some(140.0),
            GEO_CLEAR_WEB,
            133,
        );
        let st = &store.contexts[net]["bad-arm"];
        assert_eq!(st.circuit, CircuitState::Closed);
        assert_eq!(st.consecutive_failures, 0);
    }

    #[test]
    fn diverse_slate_picks_distinct_protocol_families_before_duplicates() {
        let mut store = ContextualBanditStore::default();
        let net = "wifi:office";
        for t in 1..=4 {
            store.record_outcome(net, "x1", "xray", true, Some(90.0), GEO_CLEAR_WEB, t);
            store.record_outcome(net, "x2", "xray", true, Some(105.0), GEO_CLEAR_WEB, t);
            store.record_outcome(net, "q1", "quic", true, Some(150.0), GEO_CLEAR_WEB, t);
            store.record_outcome(net, "w1", "wireguard", true, Some(170.0), GEO_CLEAR_WEB, t);
        }

        let pool = vec![
            cand("x1", "xray"),
            cand("x2", "xray"),
            cand("q1", "quic"),
            cand("w1", "wireguard"),
        ];
        let slate = store.select_diverse_slate(net, &pool, AutopilotIntent::BalancedWeb, 3, 10);
        let mut families = HashSet::new();
        for c in &slate {
            families.insert(c.protocol_family.to_ascii_lowercase());
        }
        assert_eq!(slate.len(), 3);
        assert_eq!(slate[0].arm_id, "x1");
        assert!(families.contains("xray"));
        assert!(families.contains("quic"));
        assert!(families.contains("wireguard"));
        assert_eq!(
            families.len(),
            3,
            "Happy Eyeballs slate must maximize protocol diversity: {slate:?}"
        );
    }

    #[test]
    fn hysteresis_prevents_flapping_on_marginal_gains() {
        // Healthy route at 0.80 cannot be preempted by 0.88 (+10%) even with high streak.
        assert!(!should_preempt_active(true, 0.80, 0.88, 5));
        // Healthy route at 0.80 is NOT preempted on single outlier observation.
        assert!(!should_preempt_active(true, 0.80, 1.10, 1));
        // Healthy route IS preempted once >=25% gain holds for >=2 ticks.
        assert!(should_preempt_active(true, 0.80, 1.05, 2));
        // Unhealthy route is always preempted immediately.
        assert!(should_preempt_active(false, 0.80, 0.20, 0));
    }
}
