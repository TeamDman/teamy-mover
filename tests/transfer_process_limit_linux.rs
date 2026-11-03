#![cfg(target_os = "linux")]

use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::process::Command;
use teamy_mover::transfer::process_limit::{
    MAX_ADDRESS_SPACE_BYTES, apply_linux_address_space_limit,
};

#[test]
fn address_space_limit_child() {
    if std::env::var_os("TEAMY_TEST_LIMIT_CHILD").is_none() {
        return;
    }
    if std::env::var_os("TEAMY_TEST_LIMIT_STRICT").is_some() {
        let old = getrlimit(Resource::As);
        let tighter = (240_u64 * 1024 * 1024)
            .min(old.current.unwrap_or(u64::MAX))
            .min(old.maximum.unwrap_or(u64::MAX));
        setrlimit(
            Resource::As,
            Rlimit {
                current: Some(tighter),
                maximum: Some(tighter),
            },
        )
        .unwrap();
    }
    let previous = getrlimit(Resource::As);
    apply_linux_address_space_limit().unwrap();
    let current = getrlimit(Resource::As);
    let maximum = current.maximum.expect("hard limit must be finite");
    assert_eq!(current.current, Some(maximum));
    assert!(maximum <= MAX_ADDRESS_SPACE_BYTES);
    if let Some(old) = previous.current {
        assert!(maximum <= old);
    }
    if let Some(old) = previous.maximum {
        assert!(maximum <= old);
    }
    let mut allocation = Vec::<u8>::new();
    assert!(allocation.try_reserve_exact(512 * 1024 * 1024).is_err());
}

#[test]
fn address_space_limit_is_enforced_in_a_separate_process() {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "address_space_limit_child"])
        .env("TEAMY_TEST_LIMIT_CHILD", "1")
        .status()
        .unwrap();
    assert!(result.success(), "address-space limit child failed");
}

#[test]
fn address_space_limit_preserves_a_stricter_inherited_limit() {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "address_space_limit_child"])
        .env("TEAMY_TEST_LIMIT_CHILD", "1")
        .env("TEAMY_TEST_LIMIT_STRICT", "1")
        .status()
        .unwrap();
    assert!(result.success(), "stricter-limit child failed");
}
