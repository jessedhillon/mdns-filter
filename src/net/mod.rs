//! Network interface and socket handling.

pub mod interface;
pub mod socket;

pub use interface::InterfaceInfo;
pub use socket::{create_multicast_socket, InterfaceSocket};
