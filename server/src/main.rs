use clap::{Parser, Subcommand};
use colored::*;
use innernet_shared::{
    AddCidrOpts, AddPeerOpts, DelegationOpts, DeleteCidrOpts, EnableDisablePeerOpts, HostsOpts,
    NetworkOpts, RenameCidrOpts, RenamePeerOpts,
};
use std::{env, path::PathBuf};

use innernet_client_core::admin;
use innernet_server::{
    initialize::{self, InitializeOpts},
    serve, uninstall, AdminClient, ServerConfig,
};
use innernet_shared::Interface;

#[derive(Debug, Parser)]
#[command(name = "innernet-server", author, version, about)]
struct Opts {
    #[clap(subcommand)]
    command: Command,

    #[clap(short, long, default_value = "/etc/innernet-server")]
    config_dir: PathBuf,

    #[cfg_attr(
        not(target_os = "openbsd"),
        clap(short, long, default_value = "/var/lib/innernet-server")
    )]
    #[cfg_attr(
        target_os = "openbsd",
        clap(short, long, default_value = "/var/db/innernet-server")
    )]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new network.
    #[clap(alias = "init")]
    New {
        #[clap(flatten)]
        opts: InitializeOpts,
    },

    /// Permanently uninstall a created network, rendering it unusable. Use with care.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Serve the coordinating server for an existing network.
    Serve {
        interface: Interface,

        #[clap(flatten)]
        network: NetworkOpts,

        #[clap(flatten)]
        hosts: HostsOpts,
    },

    /// Add a peer to an existing network.
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        args: AddPeerOpts,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Delegate a prefix of a peer's CIDR to the peer.
    ///
    /// The prefix must be aligned, lie within the peer's CIDR, hold neither the network nor the
    /// broadcast address of the CIDR, and share no address with another delegation.
    AddDelegation {
        interface: Interface,

        #[clap(flatten)]
        args: DelegationOpts,
    },

    /// Withdraw a delegation from a peer.
    ///
    /// Every node that has seen the peer keeps the prefix pinned to the peer's key, and refuses it
    /// to another peer. A peer left without a delegation is in effect disabled. The server's own
    /// peer keeps the delegation that holds the server's internal address.
    WithdrawDelegation {
        interface: Interface,

        #[clap(flatten)]
        args: DelegationOpts,
    },

    /// Rename an existing peer.
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        args: RenamePeerOpts,
    },

    /// Add a new CIDR to an existing network.
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        args: AddCidrOpts,
    },

    /// Rename an existing CIDR.
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        args: RenameCidrOpts,
    },

    /// Delete a CIDR.
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        args: DeleteCidrOpts,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() {
    if env::var_os("RUST_LOG").is_none() {
        // Set some default log settings.
        env::set_var("RUST_LOG", "warn,warp=info,wg_manage_server=info");
    }

    pretty_env_logger::init();
    let opts = Opts::parse();

    if let Err(e) = run(opts).await {
        log::error!("{:#}\n", e);
        std::process::exit(1);
    }
}

async fn run(opts: Opts) -> Result<(), anyhow::Error> {
    if unsafe { libc::getuid() } != 0 && !matches!(opts.command, Command::Completions { .. }) {
        anyhow::bail!("innernet-server must run as root.");
    }

    let conf = ServerConfig::new(opts.config_dir, opts.data_dir);

    match opts.command {
        Command::New { opts } => {
            if let Err(e) = initialize::init_wizard(&conf, opts) {
                eprintln!("{}: {:#}.", "creation failed".red(), e);
                std::process::exit(1);
            }
        },
        Command::Uninstall { interface, yes } => uninstall(&interface, &conf, opts.network, yes)?,
        Command::Serve {
            interface,
            network: routing,
            hosts,
        } => serve(*interface, &conf, routing, hosts).await?,
        Command::AddPeer { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::add_peer(&rest_client, &interface, admin.server(), args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::RenamePeer { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::rename_peer(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::DisablePeer { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::enable_or_disable_peer(&rest_client, args, false)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::EnablePeer { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::enable_or_disable_peer(&rest_client, args, true)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::AddDelegation { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::add_delegation(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::WithdrawDelegation { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::withdraw_delegation(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::AddCidr { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::add_cidr(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::RenameCidr { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::rename_cidr(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::DeleteCidr { interface, args } => {
            let admin = AdminClient::new(&interface, &conf)?;
            let rest_client = admin.rest_client()?;
            admin::delete_cidr(&rest_client, args)
                .await
                .map_err(|e| admin.explain(e))?
        },
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
