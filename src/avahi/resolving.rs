use super::browsing::Service;

use std::collections::HashMap;
use std::net::{AddrParseError, IpAddr, SocketAddr};

type ResolveService = (
    i32,          //interface 0
    i32,          //protocol 1
    String,       //name 2
    String,       //service_type 3
    String,       //domain 4
    String,       //host 5
    i32,          //approtocol 6
    String,       //address 7
    u16,          //port 8
    Vec<Vec<u8>>, //txt 9
    u32,          //flags 10
);

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Resolved {
    pub service: Service,
    pub host: String,
    pub address: SocketAddr,
    pub txt: HashMap<String, String>,
}

impl TryFrom<ResolveService> for Resolved {
    type Error = AddrParseError;

    fn try_from(args: ResolveService) -> Result<Self, Self::Error> {
        let mut txt = HashMap::new();

        // Parse TXT records
        for entry in args.9 {
            if let Ok(s) = core::str::from_utf8(&entry) {
                if let Some((k, v)) = s.split_once('=') {
                    txt.insert(k.to_string(), v.to_string());
                }
            }
        }

        let result_service = Service {
            interface: args.0,
            name: args.2,
            protocol: args.1,
            service_type: args.3,
            domain: args.4,
            flags: args.10,
        };

        // Parse the socket
        let address: IpAddr = args.7.parse()?;
        let address: SocketAddr = (address, args.8).into();

        Ok(Resolved {
            host: args.5.to_string(),
            service: result_service,
            address,
            txt,
        })
    }
}
