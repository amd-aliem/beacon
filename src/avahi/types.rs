#[zbus::proxy(
    interface = "org.freedesktop.Avahi.Server",
    default_service = "org.freedesktop.Avahi",
    default_path = "/"
)]
pub trait Server {
    /// Create a new service browser
    #[allow(clippy::too_many_arguments)]
    fn service_browser_new(
        &self,
        interface: i32,
        protocol: i32,
        service_type: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;

    #[allow(clippy::too_many_arguments)]
    fn resolve_service(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        aprotocol: i32, // -1 for any, 0 for IPv4, 1 for IPv6
        flags: u32,
    ) -> zbus::Result<(
        i32,          // interface
        i32,          // protocol
        String,       // name
        String,       // type
        String,       // domain
        String,       // host
        i32,          // aprotocol
        String,       // address
        u16,          // port
        Vec<Vec<u8>>, // txt
        u32,          // flags
    )>;
}

/// Service browser proxy for receiving service discovery notifications
#[zbus::proxy(
    interface = "org.freedesktop.Avahi.ServiceBrowser",
    default_service = "org.freedesktop.Avahi"
)]
pub trait ServiceBrowser {
    /// Signal emitted when a new service is discovered
    #[zbus(signal)]
    fn item_new(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        flags: u32,
    ) -> zbus::Result<()>;
}

/// Service resolver proxy for resolving service details
#[zbus::proxy(
    interface = "org.freedesktop.Avahi.ServiceResolver",
    default_service = "org.freedesktop.Avahi"
)]
pub trait ServiceResolver {
    /// Signal emitted when service details are successfully resolved
    #[zbus(signal)]
    fn found(
        &self,
        interface: i32,
        protocol: i32,
        name: &str,
        service_type: &str,
        domain: &str,
        host: &str,
        aprotocol: i32,
        address: &str,
        port: u16,
        txt: Vec<Vec<u8>>,
        flags: u32,
    ) -> zbus::Result<()>;

    /// Signal emitted when service resolution fails
    #[zbus(signal)]
    fn failure(&self, error: &str) -> zbus::Result<()>;
}
