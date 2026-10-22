//! What peers claim, as it is pinned to their keys, and how the claims of announcements that
//! change it are decided against what is pinned to other keys.

use innernet_shared::{announcement::Announcement, Hostname, Prefix};
use std::fmt::{self, Display, Formatter};

/// What a peer claims, as it is pinned to its key: its delegation and its name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Claim {
    pub delegation: Vec<Prefix>,
    pub name: Option<Hostname>,
}

impl Claim {
    /// What `announcement` claims.
    pub fn announced(announcement: &Announcement) -> Self {
        Self {
            delegation: announcement.claims.delegation.clone(),
            name: announcement.claims.name.clone(),
        }
    }

    /// What an unsigned announcement, `announcement`, pins, beside `pinned`, what is pinned to
    /// the key already: it can't release anything, so a prefix that it leaves out stays pinned,
    /// and so does the name pinned already, whatever name it claims. The coordinator makes such
    /// announcements for a peer that has never announced, so what such a peer holds stays pinned
    /// to its key until it first signs an announcement.
    pub fn unsigned(announcement: &Announcement, pinned: &Claim) -> Self {
        let mut delegation = pinned.delegation.clone();
        for prefix in &announcement.claims.delegation {
            if !delegation.contains(prefix) {
                delegation.push(*prefix);
            }
        }
        delegation.sort();
        Self {
            delegation,
            name: pinned
                .name
                .clone()
                .or_else(|| announcement.claims.name.clone()),
        }
    }
}

/// A peer whose claims change in an update: `old`, what is pinned to its key, and `new`, what it
/// now claims. Its new claims are refused whole, since one announcement makes them all.
#[derive(Clone, Debug)]
pub struct Contender {
    pub public_key: String,
    pub old: Claim,
    pub new: Claim,
}

/// What of the new claims of a [`Contender`] [`resolve`] refuses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClaimRefusal {
    pub delegation: bool,
    pub name: bool,
}

impl ClaimRefusal {
    /// Whether anything is refused.
    pub fn is_refused(&self) -> bool {
        self.delegation || self.name
    }
}

impl Contender {
    /// What stays pinned to the key of the contender once `refusal` is applied: what it had
    /// pinned of what is refused, and what it now claims of the rest.
    pub fn pinned(&self, refusal: &ClaimRefusal) -> Claim {
        Claim {
            delegation: if refusal.delegation {
                self.old.delegation.clone()
            } else {
                self.new.delegation.clone()
            },
            name: if refusal.name {
                self.old.name.clone()
            } else {
                self.new.name.clone()
            },
        }
    }

    /// Whether `prefix`, which the contender now claims, is new to it: whether no prefix pinned
    /// to its key holds it.
    fn newly_claims(&self, prefix: &Prefix) -> bool {
        !self.old.delegation.iter().any(|old| old.contains(prefix))
    }

    /// What the new claims of the contender conflict with among `others`, what is pinned to the
    /// other keys, each with its public key, or `None` if nothing does: a prefix new to it that
    /// overlaps a prefix of another key, or a name new to it that another key holds.
    pub fn conflict<'a>(
        &self,
        others: impl IntoIterator<Item = (&'a str, &'a Claim)> + Clone,
    ) -> Option<Conflict> {
        for claimed in &self.new.delegation {
            if !self.newly_claims(claimed) {
                continue;
            }
            for (key, other) in others.clone() {
                if key == self.public_key {
                    continue;
                }
                if let Some(held) = other.delegation.iter().find(|held| held.overlaps(claimed)) {
                    return Some(Conflict::Prefix {
                        claimed: *claimed,
                        held: *held,
                        holder: key.to_string(),
                    });
                }
            }
        }
        if let Some(name) = self
            .new
            .name
            .as_ref()
            .filter(|_| self.new.name != self.old.name)
        {
            for (key, other) in others {
                if key != self.public_key && other.name.as_ref() == Some(name) {
                    return Some(Conflict::Name {
                        name: name.clone(),
                        holder: key.to_string(),
                    });
                }
            }
        }
        None
    }
}

/// What a claim that is refused conflicts with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Conflict {
    /// The claimed prefix `claimed` overlaps `held`, pinned to the key `holder`.
    Prefix {
        claimed: Prefix,
        held: Prefix,
        holder: String,
    },
    /// The claimed name is pinned to the key `holder`.
    Name { name: Hostname, holder: String },
    /// Another announcement of the same update newly claims the same.
    Contested,
}

impl Display for Conflict {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefix {
                claimed,
                held,
                holder,
            } => write!(
                f,
                "{claimed} overlaps {held}, which the peer with public key {holder} claims"
            ),
            Self::Name { name, holder } => write!(
                f,
                "the peer with public key {holder} claims the name {name}"
            ),
            Self::Contested => f.write_str("another peer newly claims the same in the same update"),
        }
    }
}

/// Decides which new claims of `contenders` are refused, given `fixed`, what is pinned to the
/// keys of the other peers, which doesn't change. A new claim is refused when it conflicts with
/// what another key ends up with, a prefix that overlaps one of its prefixes, or the same name,
/// unless that is new to the other key too, in which case both are refused. A refused claim
/// leaves what the contender had pinned, which may in turn conflict with the new claim of
/// another, so refusals are repeated until none conflicts. A contender whose claim is refused
/// loses all of its new claims.
pub fn resolve(fixed: &[(&str, &Claim)], contenders: &[Contender]) -> Vec<ClaimRefusal> {
    let mut refusals = vec![ClaimRefusal::default(); contenders.len()];
    loop {
        let pinned: Vec<Claim> = contenders
            .iter()
            .zip(&refusals)
            .map(|(contender, refusal)| contender.pinned(refusal))
            .collect();
        // What every key other than `key` ends up with.
        let others = |key: &str| -> Vec<&Claim> {
            fixed
                .iter()
                .map(|(other, claim)| (*other, *claim))
                .chain(
                    contenders
                        .iter()
                        .zip(&pinned)
                        .map(|(other, claim)| (other.public_key.as_str(), claim)),
                )
                .filter(|(other, _)| *other != key)
                .map(|(_, claim)| claim)
                .collect()
        };
        let mut changed = false;
        for (index, contender) in contenders.iter().enumerate() {
            let refusal = &mut refusals[index];
            let claim = &pinned[index];
            let others = others(&contender.public_key);
            let delegation_conflicts = !refusal.delegation
                && claim.delegation.iter().any(|prefix| {
                    contender.newly_claims(prefix)
                        && others
                            .iter()
                            .any(|other| other.delegation.iter().any(|held| held.overlaps(prefix)))
                });
            let name_conflicts = !refusal.name
                && claim.name.is_some()
                && claim.name != contender.old.name
                && others.iter().any(|other| other.name == claim.name);
            if delegation_conflicts || name_conflicts {
                refusal.delegation = true;
                refusal.name = true;
                changed = true;
            }
        }
        if !changed {
            return refusals;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(delegation: &[&str], name: Option<&str>) -> Claim {
        Claim {
            delegation: delegation.iter().map(|p| p.parse().unwrap()).collect(),
            name: name.map(|name| name.parse().unwrap()),
        }
    }

    fn contender(key: &str, old: Claim, new: Claim) -> Contender {
        Contender {
            public_key: key.into(),
            old,
            new,
        }
    }

    #[test]
    fn test_unsigned_releases_nothing() {
        let pinned = claim(&["10.0.0.1/32"], Some("a"));
        let announcement = Announcement {
            claims: innernet_shared::announcement::Claims {
                delegation: vec!["10.0.0.2/32".parse().unwrap()],
                name: Some("b".parse().unwrap()),
            },
            ..Default::default()
        };
        assert_eq!(
            Claim::unsigned(&announcement, &pinned),
            claim(&["10.0.0.1/32", "10.0.0.2/32"], Some("a"))
        );
        assert_eq!(
            Claim::unsigned(&announcement, &Claim::default()),
            Claim::announced(&announcement)
        );
    }

    #[test]
    fn test_resolve() {
        let a = claim(&["10.0.1.0/24"], Some("a"));
        let fixed = [("A", &a)];

        // A new claim within what another key holds is refused whole, and keeps what was pinned.
        let grabbing = contender(
            "B",
            claim(&["10.0.2.0/24"], Some("b")),
            claim(&["10.0.2.0/24", "10.0.1.128/25"], Some("b")),
        );
        let refusals = resolve(&fixed, std::slice::from_ref(&grabbing));
        assert!(refusals[0].is_refused());
        assert_eq!(grabbing.pinned(&refusals[0]), grabbing.old);
        assert_eq!(
            grabbing.conflict(fixed),
            Some(Conflict::Prefix {
                claimed: "10.0.1.128/25".parse().unwrap(),
                held: "10.0.1.0/24".parse().unwrap(),
                holder: "A".into(),
            })
        );

        // So is a name that another key holds, but not a name that the key holds already.
        let naming = contender("B", Claim::default(), claim(&[], Some("a")));
        assert!(resolve(&fixed, std::slice::from_ref(&naming))[0].is_refused());
        assert_eq!(
            naming.conflict(fixed),
            Some(Conflict::Name {
                name: "a".parse().unwrap(),
                holder: "A".into(),
            })
        );
        let keeping = contender("A", a.clone(), a.clone());
        assert!(!resolve(&[], std::slice::from_ref(&keeping))[0].is_refused());

        // What one key drops, another may take in the same update, while two keys that claim the
        // same new prefix are both refused.
        let mover = contender("A", a.clone(), claim(&["10.0.3.0/24"], Some("moved")));
        let taker = contender("B", Claim::default(), claim(&["10.0.1.0/24"], Some("a")));
        assert_eq!(
            resolve(&[], &[mover.clone(), taker]),
            [ClaimRefusal::default(); 2]
        );
        let other = contender("B", Claim::default(), claim(&["10.0.3.0/25"], None));
        assert!(resolve(&[], &[mover, other])
            .iter()
            .all(ClaimRefusal::is_refused));
    }
}
