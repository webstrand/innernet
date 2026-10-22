use crate::{
    config::CoordinatorTable,
    db::{self, DatabaseCidr, DatabasePeer},
    ConfigFile, Interface, Path, ServerConfig,
};
use anyhow::{anyhow, bail, Context as _, Error};
use clap::Parser;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Input};
use indoc::printdoc;
use innernet_node::Store;
use innernet_publicip::Preference;
use innernet_shared::{
    interface_config::InterfaceInfo, prompts, Endpoint, IpNetExt, PeerContents, Prefix,
    PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use ipnet::IpNet;
use std::{
    fs::{self, OpenOptions},
    io::{self, IsTerminal},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
};
use wireguard_control::KeyPair;

/// Creates the database at `database_path`, which must not exist yet, readable by its owner only,
/// as the config is, of the schema of every node and the coordinator's annex, for the network
/// `network`.
fn create_database(database_path: &Path, network: IpNet) -> Result<Store, Error> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(database_path)
        .with_context(|| format!("failed to create {}", database_path.display()))?;
    Store::open(database_path, network, Some(db::create_annex()))
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Parser)]
pub struct InitializeOpts {
    /// The network name (ex: evilcorp)
    #[clap(long)]
    pub network_name: Option<Interface>,

    /// The network CIDR (ex: 10.42.0.0/16)
    #[clap(long)]
    pub network_cidr: Option<IpNet>,

    /// This server's external endpoint (ex: 100.100.100.100:51820)
    #[clap(long, conflicts_with = "auto_external_endpoint")]
    pub external_endpoint: Option<Endpoint>,

    /// Auto-resolve external endpoint
    #[clap(long = "auto-external-endpoint")]
    pub auto_external_endpoint: bool,

    /// Port to listen on (for the WireGuard interface)
    #[clap(long)]
    pub listen_port: Option<u16>,

    /// UDP port of the TLS API, over QUIC at the server's internal address (default: a free port,
    /// which an interactive run offers to change)
    #[clap(long)]
    pub quic_port: Option<u16>,
}

struct DbInitData {
    network_name: String,
    network_cidr: IpNet,
    server_cidr: IpNet,
    our_ip: IpAddr,
    public_key_base64: String,
    endpoint: Endpoint,
}

fn populate_database(store: &Store, db_init_data: DbInitData) -> Result<(), Error> {
    const SERVER_NAME: &str = "innernet-server";

    DatabaseCidr::create(
        store,
        db_init_data.network_name.clone(),
        Prefix::new(db_init_data.network_cidr.trunc())?,
    )
    .map_err(|_| anyhow!("failed to create root CIDR"))?;

    // Every peer sees the peers of the server's CIDR, which its delegation gives it.
    let server_cidr = DatabaseCidr::create(
        store,
        SERVER_NAME.into(),
        Prefix::new(db_init_data.server_cidr)?,
    )
    .map_err(|_| anyhow!("failed to create innernet-server CIDR"))?;
    DatabaseCidr::set_infra(store, &server_cidr.prefix)?;

    DatabasePeer::create(
        store,
        PeerContents {
            name: Some(SERVER_NAME.parse().map_err(|e: &str| anyhow!(e))?),
            delegations: vec![Prefix::host(db_init_data.our_ip)],
            public_key: db_init_data.public_key_base64,
            endpoint: Some(db_init_data.endpoint),
            is_admin: true,
            is_disabled: false,
            is_redeemed: true,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            invite_expires: None,
            candidates: vec![],
            announcement: None,
            allowed_ips: None,
            primary_ip: None,
            nameserver: None,
        },
    )
    .map_err(|_| anyhow!("failed to create innernet peer."))?;

    Ok(())
}

pub fn init_wizard(conf: &ServerConfig, opts: InitializeOpts) -> Result<(), Error> {
    let theme = ColorfulTheme::default();

    innernet_shared::ensure_dirs_exist(&[conf.config_dir(), conf.database_dir()]).map_err(
        |_| {
            anyhow!(
                "Failed to create config and database directories {}",
                "(are you not running as root?)".bold()
            )
        },
    )?;
    printdoc!(
        "\nTime to setup your innernet network.

        Your network name can be any hostname-valid string, i.e. \"evilcorp\", and
        your network CIDR should be in the RFC1918 IPv4 (10/8, 172.16/12, or 192.168/16), 
        or RFC4193 IPv6 (fd00::/8) ranges.

        The external endpoint specified is a <host>:<port> string that is the address clients
        will connect to. It's up to you to forward/open ports in your routers/firewalls
        as needed.

        For more usage instructions, see https://github.com/tonarino/innernet#usage
        \n"
    );

    let name: Interface = if let Some(name) = opts.network_name {
        name
    } else {
        Input::with_theme(&theme)
            .with_prompt("Network name")
            .interact()?
    };
    // A network is never initialized over an existing one, whose config holds the server's
    // private key.
    let config_path = conf.config_path(&name);
    let database_path = conf.database_path(&name);
    for path in [&config_path, &database_path] {
        if path.exists() {
            bail!(
                "network {name} already exists: {} is present.",
                path.display()
            );
        }
    }

    let root_cidr: IpNet = if let Some(cidr) = opts.network_cidr {
        cidr
    } else {
        Input::with_theme(&theme)
            .with_prompt("Network CIDR")
            .with_initial_text("10.42.0.0/16")
            // TODO(mbernat): workaround for https://github.com/console-rs/dialoguer/issues/330
            .interact_text()?
    };

    let listen_port: u16 = if let Some(listen_port) = opts.listen_port {
        listen_port
    } else {
        Input::with_theme(&theme)
            .with_prompt("Listen port")
            .default(51820)
            .interact()
            .map_err(|_| anyhow!("failed to get listen port."))?
    };

    log::info!("listen port: {}", listen_port);

    // The kernel's WireGuard holds the listen port on every address, so the TLS API, which runs
    // over QUIC at the server's internal address, needs a UDP port of its own. A free port is
    // suggested, and taken as it is when no operator is at a terminal to change it, so that
    // scripts that predate the QUIC port keep working.
    let quic_port: u16 = match opts.quic_port {
        Some(quic_port) => quic_port,
        None => {
            let unspecified = match root_cidr {
                IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            let suggested = crate::free_udp_port(unspecified, listen_port)?;
            if std::io::stdin().is_terminal() {
                Input::with_theme(&theme)
                    .with_prompt("QUIC port (UDP, for the TLS API)")
                    .default(suggested)
                    .interact()
                    .map_err(|_| anyhow!("failed to get QUIC port."))?
            } else {
                suggested
            }
        },
    };
    if quic_port == listen_port {
        bail!("the QUIC port must differ from the listen port, which WireGuard holds.");
    }

    log::info!("QUIC port: {}", quic_port);

    let endpoint: Endpoint = if let Some(endpoint) = opts.external_endpoint {
        endpoint
    } else if opts.auto_external_endpoint {
        let ip = innernet_publicip::get_any(Preference::Ipv4)
            .ok_or_else(|| anyhow!("couldn't get external IP"))?;
        SocketAddr::new(ip, listen_port).into()
    } else {
        let external_ip = prompts::ip_auto_detection_flow()?;
        prompts::input_external_endpoint(external_ip, listen_port)?
    };

    let our_ip = root_cidr
        .hosts()
        .find(|ip| root_cidr.is_assignable(ip))
        .unwrap();
    let our_keypair = KeyPair::generate();

    let network_name = name.to_string().parse()?;
    let mut interface = InterfaceInfo::new(
        &network_name,
        &our_keypair,
        IpNet::new(our_ip, root_cidr.prefix_len())?,
    );
    interface.listen_port = Some(listen_port);
    let config = ConfigFile::new(
        interface,
        CoordinatorTable {
            quic_port: Some(quic_port),
            legacy_api: true,
            bootstrap_endpoint: Some(endpoint.clone()),
        },
    );
    let db_init_data = DbInitData {
        network_name: name.to_string(),
        network_cidr: root_cidr,
        server_cidr: IpNet::new(our_ip, root_cidr.max_prefix_len())?,
        our_ip,
        public_key_base64: our_keypair.public.to_base64(),
        endpoint,
    };

    // A network that fails to initialize leaves nothing behind, so that initializing it again
    // isn't refused as an existing one.
    let created = config.write_to_path(&config_path).and_then(|()| {
        let store = create_database(&database_path, root_cidr)
            .context("failed to create the database (are you not running as root?)")?;
        populate_database(&store, db_init_data)
    });
    if let Err(e) = created {
        let journal_path = database_path.with_extension("db-journal");
        for path in [&config_path, &database_path, &journal_path] {
            match fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    log::warn!("failed to remove {}: {e}", path.display());
                },
                _ => {},
            }
        }
        return Err(e);
    }

    println!(
        "{} Created database at {}\n",
        "[*]".dimmed(),
        database_path.to_string_lossy().bold()
    );
    printdoc!(
        "
        {star} Setup finished.

            Network {interface} has been {created}, but it's not started yet!

            Your new network starts with only one peer: this innernet server. Next,
            you'll want to create additional CIDRs and peers using the commands:

                {wg_manage_server} {add_cidr} {interface}, and
                {wg_manage_server} {add_peer} {interface}
            
            See https://github.com/tonarino/innernet for more detailed instruction
            on designing your network.
        
            When you're ready to start the network, you can auto-start the server:
            
                {systemctl_enable}{interface}

    ",
        star = "[*]".dimmed(),
        interface = name.to_string().yellow(),
        created = "created".green(),
        wg_manage_server = "innernet-server".yellow(),
        add_cidr = "add-cidr".yellow(),
        add_peer = "add-peer".yellow(),
        systemctl_enable = "systemctl enable --now innernet-server@".yellow(),
    );

    Ok(())
}
