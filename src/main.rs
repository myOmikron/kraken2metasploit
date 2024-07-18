use std::collections::HashMap;
use std::env;

use clap::Parser;
use kraken_sdk::kraken::api::handler::common::schema::PageParams;
use kraken_sdk::kraken::api::handler::ports::schema::GetAllPortsQuery;
use kraken_sdk::kraken::api::handler::ports::schema::PortProtocol;
use kraken_sdk::KrakenClient;
use rorm::db::executor::Nothing;
use rorm::db::executor::One;
use rorm::db::executor::Optional;
use rorm::db::sql::value::Value;
use rorm::db::Executor;
use rorm::Database;
use rorm::DatabaseConfiguration;
use rorm::DatabaseDriver;
use tracing::debug;
use tracing::info;
use uuid::Uuid;

use crate::cli::Cli;
use crate::config::Config;

mod cli;
mod config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = Config::from_path(&cli.config_path)?;
    let db = Database::connect(DatabaseConfiguration::new(DatabaseDriver::Postgres {
        name: config.database.name,
        host: config.database.host,
        port: config.database.port,
        user: config.database.user,
        password: config.database.password,
    }))
    .await?;

    info!("Retrieving workspace");
    let row = db
        .execute::<Optional>(
            format!(
                "SELECT \"id\" FROM \"workspaces\" WHERE \"name\" = '{}' LIMIT 1",
                cli.metasploit_workspace
            ),
            vec![],
        )
        .await?;

    let Some(row) = row else {
        return Err("Invalid metasploit workspace name".to_string().into());
    };

    let meta_id: i32 = row.get(0)?;

    let kraken_sdk = KrakenClient::new(
        config.kraken.url,
        config.kraken.user,
        config.kraken.password,
        None,
        false,
    )?;

    info!("Logging in to kraken");
    kraken_sdk.login().await?;

    let workspace = Uuid::parse_str(&cli.kraken_workspace)?;

    const LIMIT: u64 = 1000;
    let mut offset = 0;

    let mut ports = vec![];
    let mut hosts = HashMap::new();

    info!("Retrieving ports");
    loop {
        let page = kraken_sdk
            .get_all_ports(
                workspace,
                GetAllPortsQuery {
                    page: PageParams {
                        limit: LIMIT,
                        offset,
                    },
                    host: None,
                    global_filter: None,
                    port_filter: None,
                },
            )
            .await?;

        for port in &page.items {
            hosts.insert(port.host.uuid, port.host.clone());
        }

        ports.extend(page.items);

        if page.total < offset + LIMIT {
            break;
        }

        offset += LIMIT;
    }

    let mut tx = db.start_transaction().await?;

    let mut meta_hosts = HashMap::new();

    info!("Inserting hosts");
    for (_, host) in hosts {
        let row = tx
            .execute::<One>(
                "INSERT INTO \"hosts\" (\"address\", \"workspace_id\") VALUES ($1, $2) RETURNING \"id\"".to_string(),
                vec![Value::IpNetwork(host.ip_addr.into()), Value::I32(meta_id)],
            )
            .await?;

        let host_id: i32 = row.get(0)?;
        meta_hosts.insert(host.uuid, host_id);
    }

    info!("Inserting ports");
    for port in ports {
        let Some(host_id) = meta_hosts.get(&port.host.uuid) else {
            debug!("Skipping port {port:?}");
            continue;
        };

        debug!("inserting: {port:?}");

        tx.execute::<Nothing>(
            "INSERT INTO \"services\" (\"host_id\", \"port\", \"proto\", \"state\", \"info\") VALUES ($1, $2, $3, 'open', $4)"
                .to_string(),
            vec![
                Value::I32(*host_id),
                Value::I32(port.port as i32),
                Value::String(match port.protocol {
                    PortProtocol::Unknown => "",
                    PortProtocol::Tcp => "tcp",
                    PortProtocol::Udp => "udp",
                    PortProtocol::Sctp => "sctp",
                }),
                Value::String(& port.comment)
            ],
        )
        .await?;
    }

    tx.commit().await?;

    db.close().await;

    Ok(())
}
