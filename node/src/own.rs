//! The node's own announcement, which every node signs alike, whatever its role.

use innernet_shared::{
    announcement::{self, Announcement, AnnouncementError, Claims, SignedAnnouncement},
    interface_config::InterfaceInfo,
    xeddsa, Endpoint, Error, PeerContents, Prefix,
};
use std::{
    collections::BTreeSet,
    sync::{Mutex, PoisonError},
};

/// The timestamp of the node's next announcement, at the time `now`: `now`, or, if the clock went
/// back, one past `last`, the timestamp of the node's last announcement, so that every node takes
/// the next announcement for newer.
pub fn next_timestamp(last: Option<u64>, now: u64) -> u64 {
    last.map_or(now, |last| now.max(last.saturating_add(1)))
}

/// Whether `next`, the node's next announcement, would change nothing but the timestamp of
/// `current`, the last signed announcement of the node that the coordinator holds, if any. Such an
/// announcement isn't made: every node already holds what it claims and states.
pub fn is_unchanged(next: &Announcement, current: Option<&Announcement>) -> bool {
    current.is_some_and(|current| {
        *current
            == Announcement {
                timestamp: current.timestamp,
                ..next.clone()
            }
    })
}

/// Signs `announcement`, the node's own, with its private key `private_key` in base64. Its
/// timestamp must be newer than `last`, that of the node's last announcement, as
/// [`next_timestamp`] makes it, or every node would refuse it as stale.
pub fn sign(
    announcement: &Announcement,
    private_key: &str,
    last: Option<u64>,
) -> Result<SignedAnnouncement, Error> {
    if let Some(last) = last.filter(|last| announcement.timestamp <= *last) {
        return Err(AnnouncementError::Stale {
            timestamp: announcement.timestamp,
            last,
        }
        .into());
    }
    let private_key = xeddsa::PrivateKey::from_base64(private_key)?;
    Ok(announcement.sign(&private_key)?)
}

/// What the node announces, as the config of its interface, `interface`, selects it from `own`,
/// its record as the coordinator assigns it, with the ranges that the server assigns it as its
/// delegations: it claims the prefixes of `delegation` that lie within one of those ranges, or
/// every range whole by default, and its name, with only the claims of `claim_types`, the types that the server
/// checks; it states the prefixes of `allowed-ips`, shrunk to the delegation that it claims, or
/// all of that delegation by default, the address of its interface as its primary IP, and its
/// endpoints, in the order in which peers try them: the preferred endpoint, then `candidates`, at
/// most [`announcement::MAX_ENDPOINTS`] in all.
///
/// The preferred endpoint is `external-endpoint`, or, if `announce-observed-endpoint` allows it,
/// `observed`, the endpoint at which the server observes this client, which also completes the
/// host of an `external-endpoint` whose host is unspecified, and otherwise comes right after the
/// preferred endpoint, before the candidates. An endpoint whose host is unspecified that can't be
/// completed isn't announced. Prefixes that the config selects beyond the assigned ranges are
/// skipped with a warning, as are prefixes that share an address with one listed before. A
/// primary IP outside the claimed delegation is announced with a warning, and the server refuses
/// it. The timestamp is `now`, or later than `last`, the timestamp of this client's last
/// announcement, if `now` isn't.
pub fn own_announcement(
    interface: &InterfaceInfo,
    own: &PeerContents,
    mut candidates: Vec<Endpoint>,
    observed: Option<&Endpoint>,
    claim_types: &[String],
    last: Option<u64>,
    now: u64,
) -> Announcement {
    let selected = match &interface.delegation {
        Some(selected) => selected.clone(),
        None => own.delegations.clone(),
    };
    let mut delegation: Vec<Prefix> = vec![];
    for prefix in selected {
        if !own.delegations.iter().any(|range| range.contains(&prefix)) {
            log::warn!(
                "not claiming {prefix}, which lies within no range assigned to this client."
            );
        } else if let Some(overlapping) = delegation.iter().find(|kept| kept.overlaps(&prefix)) {
            log::warn!("not claiming {prefix}, which overlaps {overlapping}.");
        } else {
            delegation.push(prefix);
        }
    }
    delegation.sort();

    let allowed_ips = match &interface.allowed_ips {
        Some(allowed) => {
            for prefix in allowed {
                if !delegation.iter().any(|claimed| claimed.overlaps(prefix)) {
                    log::warn!(
                        "not stating {prefix} among the allowed IPs, which lies within no \
                         claimed prefix."
                    );
                }
            }
            announcement::shrink_to(allowed, &delegation)
        },
        None => delegation.clone(),
    };

    let primary_ip = interface.address.addr();
    if !delegation
        .iter()
        .any(|prefix| prefix.contains_addr(&primary_ip))
    {
        log::warn!(
            "the primary IP {primary_ip}, the address of the interface, lies within no claimed \
             prefix, so the server refuses the announcement."
        );
    }

    let observed = observed.filter(|_| interface.announce_observed_endpoint);
    let endpoint = match (&interface.external_endpoint, observed) {
        (None, observed) => observed.cloned(),
        (Some(endpoint), Some(observed)) if endpoint.is_host_unspecified() => {
            Some(endpoint.with_host_of(observed))
        },
        (Some(endpoint), None) if endpoint.is_host_unspecified() => {
            log::warn!(
                "not announcing the endpoint {endpoint}, whose host is unspecified, since the \
                 server reports no endpoint at which it observes this client to complete it."
            );
            None
        },
        (Some(endpoint), _) => Some(endpoint.clone()),
    };
    if let Some(observed) = observed {
        if endpoint.as_ref() != Some(observed) && !candidates.contains(observed) {
            candidates.insert(0, observed.clone());
        }
    }
    let mut endpoints: Vec<Endpoint> = endpoint.into_iter().collect();
    for candidate in candidates {
        if !endpoints.contains(&candidate) {
            endpoints.push(candidate);
        }
    }
    if endpoints.len() > announcement::MAX_ENDPOINTS {
        log::debug!(
            "announcing only the first {} of {} endpoints.",
            announcement::MAX_ENDPOINTS,
            endpoints.len()
        );
        endpoints.truncate(announcement::MAX_ENDPOINTS);
    }

    let mut claims = Claims {
        delegation,
        name: own.name.clone(),
    };
    claims.retain_types(claim_types);
    Announcement {
        timestamp: next_timestamp(last, now),
        claims,
        allowed_ips,
        primary_ip: Some(primary_ip),
        endpoints,
        nameserver: None,
    }
}

/// Logs `message` as a warning, but only the first time, so that a daemon doesn't repeat it on
/// every fetch.
pub fn warn_once(message: String) {
    static WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    let mut warned = WARNED.lock().unwrap_or_else(PoisonError::into_inner);
    if !warned.contains(&message) {
        log::warn!("{message}");
        warned.insert(message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_control::KeyPair;

    #[test]
    fn test_next_timestamp() {
        assert_eq!(next_timestamp(None, 7), 7);
        assert_eq!(next_timestamp(Some(5), 7), 7);
        // A clock that went back still yields an announcement newer than the last.
        assert_eq!(next_timestamp(Some(9), 7), 10);
        assert_eq!(next_timestamp(Some(u64::MAX), 7), u64::MAX);
    }

    #[test]
    fn test_is_unchanged() {
        let current = Announcement {
            timestamp: 5,
            ..Default::default()
        };
        let next = Announcement {
            timestamp: 7,
            ..Default::default()
        };
        assert!(is_unchanged(&next, Some(&current)));
        // Nothing to compare with: the coordinator holds no signed announcement of the node.
        assert!(!is_unchanged(&next, None));
        let moved = Announcement {
            primary_ip: Some("10.0.0.2".parse().unwrap()),
            ..next
        };
        assert!(!is_unchanged(&moved, Some(&current)));
    }

    #[test]
    fn test_sign() {
        let keypair = KeyPair::generate();
        let private_key = keypair.private.to_base64();
        let announcement = Announcement {
            timestamp: 7,
            ..Default::default()
        };
        let signed = sign(&announcement, &private_key, Some(6)).unwrap();
        assert_eq!(signed.open(&keypair.public).unwrap(), announcement);
        assert!(sign(&announcement, &private_key, Some(7)).is_err());
    }

    fn config(interface: serde_json::Value) -> InterfaceInfo {
        let keypair = KeyPair::generate();
        let mut config = serde_json::json!({
            "network-name": "wg0",
            "address": "10.0.1.1/16",
            "private-key": keypair.private.to_base64(),
        });
        for (key, value) in interface.as_object().unwrap() {
            config[key] = value.clone();
        }
        serde_json::from_value(config).unwrap()
    }

    fn own() -> PeerContents {
        PeerContents {
            name: Some("own".parse().unwrap()),
            delegations: vec![
                "10.0.1.0/24".parse().unwrap(),
                "10.0.2.1/32".parse().unwrap(),
            ],
            public_key: KeyPair::generate().public.to_base64(),
            endpoint: None,
            persistent_keepalive_interval: None,
            is_admin: false,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
            nameserver: None,
        }
    }

    #[test]
    fn test_own_announcement() {
        let all_types = announcement::CLAIM_TYPES.map(String::from);
        let observed: Endpoint = "203.0.113.9:4000".parse().unwrap();
        let assigned = own().delegations;
        let check = |announcement: &Announcement| {
            announcement.check_assigned(&assigned, own().name.as_ref())
        };

        // By default, every assigned range is claimed whole, and stated as the allowed IPs, the
        // address of the interface is the primary IP, and the observed endpoint is announced as
        // the preferred endpoint, before the candidates.
        let candidates: Vec<Endpoint> = vec!["192.0.2.1:51820".parse().unwrap()];
        let announcement = own_announcement(
            &config(serde_json::json!({})),
            &own(),
            candidates.clone(),
            Some(&observed),
            &all_types,
            None,
            7,
        );
        assert_eq!(announcement.claims.delegation, own().delegations);
        assert_eq!(announcement.claims.name, own().name);
        assert_eq!(announcement.allowed_ips, own().delegations);
        assert_eq!(announcement.primary_ip, Some("10.0.1.1".parse().unwrap()));
        assert_eq!(
            announcement.endpoints,
            [observed.clone(), candidates[0].clone()]
        );
        assert_eq!(announcement.timestamp, 7);
        assert!(check(&announcement).is_ok());

        // Without an observed endpoint or candidates, there is no endpoint to announce.
        let announcement = own_announcement(
            &config(serde_json::json!({})),
            &own(),
            vec![],
            None,
            &all_types,
            None,
            7,
        );
        assert_eq!(announcement.endpoints, []);

        // The observed endpoint completes an external endpoint whose host is unspecified, and
        // otherwise comes right after the preferred endpoint.
        let unspecified = config(serde_json::json!({ "external-endpoint": "0.0.0.0:51820" }));
        let announce = |config: &InterfaceInfo, observed| {
            own_announcement(
                config,
                &own(),
                candidates.clone(),
                observed,
                &all_types,
                None,
                7,
            )
        };
        let announced = announce(&unspecified, Some(&observed));
        assert_eq!(
            announced.endpoints,
            [
                "203.0.113.9:51820".parse().unwrap(),
                observed.clone(),
                candidates[0].clone()
            ]
        );
        assert_eq!(announce(&unspecified, None).endpoints, candidates);
        let external = config(serde_json::json!({ "external-endpoint": "198.51.100.1:51820" }));
        let announced = announce(&external, Some(&observed));
        assert_eq!(
            announced.endpoints,
            [
                "198.51.100.1:51820".parse().unwrap(),
                observed.clone(),
                candidates[0].clone()
            ]
        );

        // The config narrows what is claimed and what is stated, and what it selects beyond the
        // assigned ranges, or twice, is skipped. The observed endpoint isn't announced if the
        // config says so, and the endpoints are cut to MAX_ENDPOINTS.
        let config = config(serde_json::json!({
            "external-endpoint": "198.51.100.1:51820",
            "announce-observed-endpoint": false,
            "delegation": ["10.0.1.0/25", "10.0.1.0/26", "10.0.3.0/24"],
            "allowed-ips": ["10.0.1.0/26", "10.0.0.0/16", "10.0.3.0/24"],
        }));
        let candidates: Vec<Endpoint> = (1..=12)
            .map(|port| format!("192.0.2.1:{port}").parse().unwrap())
            .collect();
        let announcement = own_announcement(
            &config,
            &own(),
            candidates.clone(),
            Some(&observed),
            &all_types,
            Some(9),
            7,
        );
        assert_eq!(
            announcement.claims.delegation,
            ["10.0.1.0/25".parse().unwrap()]
        );
        assert_eq!(announcement.allowed_ips, ["10.0.1.0/25".parse().unwrap()]);
        assert_eq!(
            announcement.endpoints[0],
            "198.51.100.1:51820".parse().unwrap()
        );
        assert!(!announcement.endpoints.contains(&observed));
        assert_eq!(announcement.endpoints.len(), announcement::MAX_ENDPOINTS);
        assert_eq!(
            announcement.endpoints[1..],
            candidates[..announcement::MAX_ENDPOINTS - 1]
        );
        // The timestamp follows the last one, even if the clock went back.
        assert_eq!(announcement.timestamp, 10);
        assert!(check(&announcement).is_ok());

        // Only the claims of the types that the server checks are announced, while the
        // statements are announced whatever it checks.
        let types = ["delegation".to_string()];
        let announcement =
            own_announcement(&config, &own(), vec![], Some(&observed), &types, None, 1);
        assert_eq!(
            announcement.claims,
            Claims {
                delegation: vec!["10.0.1.0/25".parse().unwrap()],
                ..Default::default()
            }
        );
        assert_eq!(announcement.primary_ip, Some("10.0.1.1".parse().unwrap()));

        // A client that selects nothing that it is assigned claims nothing, and its primary IP
        // then lies outside its delegation, which the server refuses.
        let config = tests::config(serde_json::json!({
            "delegation": ["10.0.3.0/24"],
        }));
        let announcement = own_announcement(&config, &own(), vec![], None, &all_types, None, 1);
        assert!(announcement.claims.delegation.is_empty());
        assert!(announcement.allowed_ips.is_empty());
        assert!(check(&announcement).is_err());
    }
}
