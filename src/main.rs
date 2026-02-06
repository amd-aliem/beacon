pub mod avahi;
pub mod uefi;

use std::net::IpAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use zbus::Connection;

use crate::avahi::Avahi;

#[derive(Parser)]
#[command(name = std::env!("CARGO_PKG_NAME"))]
#[command(about = std::env!("CARGO_PKG_DESCRIPTION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Alerts dispatch that a workload is booting.
    Boot,

    /// Asks dispatch to create a GitHub issue with test results.
    Report {
        /// The title of the GitHub issue
        #[arg(short, long)]
        title: String,

        /// Text file to use as the GitHub issue body
        ///
        /// If not specified, the body will be read from stdin.
        #[arg(short, long, value_name = "FILE")]
        body: Option<std::path::PathBuf>,

        /// Labels for the GitHub issue (can be specified multiple times)
        #[arg(short, long, action = clap::ArgAction::Append)]
        label: Vec<String>,

        /// Assignees for the GitHub issue (can be specified multiple times)
        #[arg(short, long, action = clap::ArgAction::Append)]
        assignee: Vec<String>,

        /// Milestone for the GitHub issue
        #[arg(short, long)]
        milestone: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum Action {
    Boot,
    Report(Report),
}

impl TryFrom<Cli> for Action {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Cli) -> Result<Self, Self::Error> {
        match value.command {
            Commands::Boot => Ok(Action::Boot),
            Commands::Report {
                title,
                body,
                label,
                assignee,
                milestone,
            } => Ok(Action::Report(Report {
                title,
                body: body
                    .map(std::fs::read_to_string)
                    .unwrap_or_else(|| std::io::read_to_string(std::io::stdin().lock()))?,
                labels: label,
                assignees: assignee,
                milestone,
            })),
        }
    }
}

impl Action {
    async fn perform(&self, url: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Send the appropriate request based on action
        let response = match self {
            Action::Boot => Client::new().post(url).send().await?,
            Action::Report(report) => Client::new().put(url).json(report).send().await?,
        };

        // Handle the response
        match response.status() {
            // This is the normal error when the service worked,
            // but no task was found for our IP address. This either
            // means that there is no job or that we need to contact
            // the server on a different address. Skip.
            StatusCode::EXPECTATION_FAILED => Ok(false),
            StatusCode::OK => {
                self.fetch_sshkey(url).await;
                Ok(true)
            }
            status => {
                eprintln!("warning: {status}");
                Ok(false)
            }
        }
    }

    async fn fetch_sshkey(&self, url: &str) {
        if !matches!(self, Action::Boot) {
            return;
        }

        // Strip query string from URL before appending /ssh-key
        let base_url = url.split('?').next().unwrap_or(url);
        let ssh_key_url = format!("{}/ssh-key", base_url);
        let response = match Client::new().get(&ssh_key_url).send().await {
            Ok(r) => r,
            Err(e) => return eprintln!("warning: failed to fetch SSH key: {}", e),
        };

        match response.status() {
            StatusCode::OK => {
                if let Ok(ssh_key) = response.text().await {
                    if let Err(e) = install_ssh_key(&ssh_key).await {
                        eprintln!("warning: failed to install SSH key: {}", e);
                    }
                }
            }
            StatusCode::NOT_FOUND => {} // No SSH key configured
            status => eprintln!("warning: SSH key fetch returned {}", status),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    title: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    body: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    labels: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    assignees: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    milestone: Option<String>,
}

const RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);
const BROWSER_TIMEOUT: Duration = Duration::from_secs(10);

async fn install_ssh_key(ssh_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::io::AsyncWriteExt;

    // Determine SSH directory (typically /root/.ssh for root user)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let ssh_dir = std::path::Path::new(&home).join(".ssh");
    let authorized_keys_path = ssh_dir.join("authorized_keys");

    // Create .ssh directory if it doesn't exist
    fs::create_dir_all(&ssh_dir).await?;

    // Set permissions on .ssh directory (700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&ssh_dir).await?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&ssh_dir, perms).await?;
    }

    // Read existing authorized_keys if it exists
    let existing_keys = fs::read_to_string(&authorized_keys_path)
        .await
        .unwrap_or_default();

    // Check if the key already exists
    if existing_keys
        .lines()
        .any(|line| line.trim() == ssh_key.trim())
    {
        // Key already exists, no need to add it again
        return Ok(());
    }

    // Append the new key
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&authorized_keys_path)
        .await?;

    // Add newline if file doesn't end with one
    if !existing_keys.is_empty() && !existing_keys.ends_with('\n') {
        file.write_all(b"\n").await?;
    }

    file.write_all(ssh_key.trim().as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;

    // Set permissions on authorized_keys (600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&authorized_keys_path).await?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&authorized_keys_path, perms).await?;
    }

    Ok(())
}

// Avahi D-Bus proxy interfaces
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let action: Action = Cli::parse().try_into()?;

    for url in uefi::find_urls().await? {
        match action.perform(&url).await {
            Ok(true) => return Ok(()),
            Ok(false) => continue,
            Err(e) => eprintln!("error: {}: {}", url, e),
        }
    }

    let connection = Connection::system().await?;
    let avahi = Avahi::new(&connection).await?;

    let mut browsing = avahi.browse(-1, -1, "_dispatch._tcp", "local", 0).await?;
    while let Ok(Some(item)) = timeout(BROWSER_TIMEOUT, browsing.next()).await {
        let resolved = timeout(RESOLVER_TIMEOUT, avahi.resolve(item)).await?;

        match resolved {
            Ok(resolved) => {
                match resolved.address.ip() {
                    addr if addr.is_loopback() => continue,
                    IpAddr::V4(ipv4) if ipv4.is_link_local() => continue,
                    IpAddr::V6(ipv6) if ipv6.is_unicast_link_local() => continue,
                    _ => {}
                }

                // Construct the URL
                let url = match resolved.txt.get("path") {
                    Some(path) => format!("http://{}{}", resolved.address, path),
                    None => continue,
                };
                match action.perform(&url).await {
                    Ok(true) => std::process::exit(0),
                    Ok(false) => continue,

                    Err(e) => eprintln!("error: {}: {}", url, e),
                }
            }
            Err(e) => eprintln!("Warning: Resolve failed: {e}"),
        }
    }

    Err("no dispatch services found".into())
}
