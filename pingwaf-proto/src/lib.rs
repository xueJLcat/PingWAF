/// Generated gRPC code for PingWAF control plane protocol
#[allow(clippy::all)]
#[allow(warnings)]
pub mod control_plane {
    tonic::include_proto!("pingwaf");
}

// Re-export commonly used types at crate root for convenience
pub use control_plane::*;

/// Per-process socket budget and upper bound for a heartbeat's inventory.
pub const MAX_INGRESS_LISTENERS: usize = 32;

pub const MANAGED_PROTOCOL_VERSION: u32 = 1;
