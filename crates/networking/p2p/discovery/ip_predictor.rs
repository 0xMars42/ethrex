use ethrex_common::H256;
use rustc_hash::{FxHashMap, FxHashSet};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

/// Time window for collecting IP votes from PONG recipient_addr.
const IP_VOTE_WINDOW: Duration = Duration::from_secs(300);
/// Minimum number of agreeing votes required to update external IP.
const IP_VOTE_THRESHOLD: usize = 3;

/// Tracks PONG-observed external IPs from multiple peers and returns a
/// winning IP once quorum is reached, shared across discv4 and discv5.
#[derive(Debug, Default)]
pub struct IpPredictor {
    /// Collects reported IPs from PONGs, keyed by IP, value is set of voter node-ids.
    pub ip_votes: FxHashMap<IpAddr, FxHashSet<H256>>,
    /// When the current IP voting period started. None if no votes received yet.
    pub ip_vote_period_start: Option<Instant>,
    /// Whether the first (fast) voting round has completed.
    pub first_ip_vote_round_completed: bool,
}

impl IpPredictor {
    /// Records an IP vote from a PONG-observed address.
    /// Returns `Some(ip)` if the voting round ended with a winning IP to apply.
    pub fn record_ip_vote(&mut self, reported_ip: IpAddr, voter_id: H256) -> Option<IpAddr> {
        if Self::is_private_ip(reported_ip) {
            return None;
        }

        let now = Instant::now();

        if self.ip_vote_period_start.is_none() {
            self.ip_vote_period_start = Some(now);
        }

        self.ip_votes
            .entry(reported_ip)
            .or_default()
            .insert(voter_id);

        let total_votes: usize = self.ip_votes.values().map(|v| v.len()).sum();
        let round_ended = if !self.first_ip_vote_round_completed {
            total_votes >= IP_VOTE_THRESHOLD
        } else {
            self.ip_vote_period_start
                .is_some_and(|start| now.duration_since(start) >= IP_VOTE_WINDOW)
        };

        if round_ended {
            return self.finalize_ip_vote_round();
        }
        None
    }

    /// Checks whether the current voting period has timed out and finalizes it.
    /// Returns `Some(ip)` if a timed-out round produced a winning IP to apply.
    pub fn check_timeout(&mut self) -> Option<IpAddr> {
        let now = Instant::now();
        if let Some(start) = self.ip_vote_period_start
            && now.duration_since(start) >= IP_VOTE_WINDOW
        {
            return self.finalize_ip_vote_round();
        }
        None
    }

    /// Finalizes the current voting round.
    /// Returns `Some(winning_ip)` if a winner reached the threshold and should be applied.
    fn finalize_ip_vote_round(&mut self) -> Option<IpAddr> {
        let winner = self
            .ip_votes
            .iter()
            .map(|(ip, voters)| (*ip, voters.len()))
            .max_by_key(|(_, count)| *count);

        let result = winner.and_then(|(winning_ip, vote_count)| {
            (vote_count >= IP_VOTE_THRESHOLD).then_some(winning_ip)
        });

        self.ip_votes.clear();
        self.ip_vote_period_start = Some(Instant::now());
        self.first_ip_vote_round_completed = true;

        result
    }

    /// Returns true if the IP is private/local (not useful for external connectivity).
    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // unique local (fc00::/7)
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    // link-local (fe80::/10)
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_voting_returns_winning_ip() {
        let mut predictor = IpPredictor::default();

        let new_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let voter1 = H256::from_low_u64_be(1);
        let voter2 = H256::from_low_u64_be(2);
        let voter3 = H256::from_low_u64_be(3);

        assert_eq!(predictor.record_ip_vote(new_ip, voter1), None);
        assert_eq!(predictor.record_ip_vote(new_ip, voter2), None);
        // Third vote triggers round end, returns the winning IP
        assert_eq!(predictor.record_ip_vote(new_ip, voter3), Some(new_ip));
        assert!(predictor.ip_votes.is_empty());
    }

    #[tokio::test]
    async fn test_ip_voting_same_peer_votes_once() {
        let mut predictor = IpPredictor::default();

        let new_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let same_voter = H256::from_low_u64_be(1);

        predictor.record_ip_vote(new_ip, same_voter);
        predictor.record_ip_vote(new_ip, same_voter);
        predictor.record_ip_vote(new_ip, same_voter);

        assert_eq!(predictor.ip_votes.get(&new_ip).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn test_ip_voting_ignores_private_ips() {
        let mut predictor = IpPredictor::default();

        let voter1 = H256::from_low_u64_be(1);

        let private_ip: IpAddr = "192.168.1.100".parse().unwrap();
        predictor.record_ip_vote(private_ip, voter1);
        assert!(predictor.ip_votes.is_empty());

        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        predictor.record_ip_vote(loopback, voter1);
        assert!(predictor.ip_votes.is_empty());

        let public_ip: IpAddr = "203.0.113.50".parse().unwrap();
        predictor.record_ip_vote(public_ip, voter1);
        assert_eq!(predictor.ip_votes.get(&public_ip).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn test_ip_voting_split_votes_no_winner() {
        let mut predictor = IpPredictor::default();

        let ip1: IpAddr = "203.0.113.50".parse().unwrap();
        let ip2: IpAddr = "203.0.113.51".parse().unwrap();
        let voter1 = H256::from_low_u64_be(1);
        let voter2 = H256::from_low_u64_be(2);
        let voter3 = H256::from_low_u64_be(3);

        predictor.record_ip_vote(ip1, voter1);
        predictor.record_ip_vote(ip2, voter2);
        // ip1 has 2 votes, ip2 has 1 — ip1 wins but only has 2 < threshold 3
        assert_eq!(predictor.record_ip_vote(ip1, voter3), None);
        assert!(predictor.ip_votes.is_empty());
        assert!(predictor.first_ip_vote_round_completed);
    }

    #[tokio::test]
    async fn test_ip_vote_cleanup() {
        let mut predictor = IpPredictor::default();

        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        let voter1 = H256::from_low_u64_be(1);

        let mut voters = FxHashSet::default();
        voters.insert(voter1);
        predictor.ip_votes.insert(ip, voters);
        predictor.ip_vote_period_start = Some(Instant::now());
        assert_eq!(predictor.ip_votes.len(), 1);

        // check_timeout should retain votes (round hasn't timed out yet)
        assert_eq!(predictor.check_timeout(), None);
        assert_eq!(predictor.ip_votes.len(), 1);
        assert!(!predictor.first_ip_vote_round_completed);
    }

    #[tokio::test]
    async fn test_discv4_pong_observation_feeds_predictor() {
        let mut predictor = IpPredictor::default();

        let public_ip: IpAddr = "203.0.113.42".parse().unwrap();
        let voter1 = H256::from_low_u64_be(1);
        let voter2 = H256::from_low_u64_be(2);
        let voter3 = H256::from_low_u64_be(3);

        assert_eq!(predictor.record_ip_vote(public_ip, voter1), None);
        assert_eq!(predictor.record_ip_vote(public_ip, voter2), None);
        // Third distinct voter triggers round completion
        assert_eq!(predictor.record_ip_vote(public_ip, voter3), Some(public_ip));
    }
}
