use anyhow::{anyhow, Result};
use redis::{aio::MultiplexedConnection, Client};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Manages connections to Redis Sentinel cluster with automatic failover detection
pub struct SentinelConnectionManager {
    sentinel_clients: Vec<Client>,
    master_name: String,
    sentinel_password: Option<String>,
    current_master: Arc<RwLock<Option<Client>>>,
    db: u8,
}

impl SentinelConnectionManager {
    /// Create a new Sentinel connection manager
    ///
    /// # Arguments
    /// * `sentinel_urls` - List of Sentinel node URLs (e.g., ["redis://localhost:26379"])
    /// * `master_name` - Name of the master to monitor (e.g., "mymaster")
    /// * `sentinel_password` - Optional password for Sentinel authentication
    /// * `db` - Redis database number (0-15)
    pub async fn new(
        sentinel_urls: Vec<String>,
        master_name: String,
        sentinel_password: Option<String>,
        db: u8,
    ) -> Result<Self> {
        // Create clients for each Sentinel node
        let sentinel_clients: Vec<Client> = sentinel_urls
            .iter()
            .map(|url| Client::open(url.as_str()))
            .collect::<Result<Vec<_>, _>>()?;

        if sentinel_clients.is_empty() {
            return Err(anyhow!("No Sentinel nodes configured"));
        }

        let manager = Self {
            sentinel_clients,
            master_name: master_name.clone(),
            sentinel_password,
            current_master: Arc::new(RwLock::new(None)),
            db,
        };

        // Discover master on startup
        manager.discover_master().await?;

        // Spawn background monitor for failover detection
        manager.spawn_monitor();

        tracing::info!(
            master_name = %master_name,
            sentinel_count = manager.sentinel_clients.len(),
            "Redis Sentinel connection manager initialized"
        );

        Ok(manager)
    }

    /// Discover the current master from Sentinel nodes
    async fn discover_master(&self) -> Result<String> {
        for (idx, sentinel) in self.sentinel_clients.iter().enumerate() {
            match self.query_master(sentinel).await {
                Ok(master_addr) => {
                    tracing::info!(
                        sentinel_idx = idx,
                        master = %master_addr,
                        "Discovered Redis master via Sentinel"
                    );

                    // Connect to master with DB selection
                    let master_url = if self.db > 0 {
                        format!("{}/{}", master_addr, self.db)
                    } else {
                        master_addr.clone()
                    };

                    let master_client = Client::open(master_url.as_str())?;
                    *self.current_master.write().await = Some(master_client);

                    return Ok(master_addr);
                }
                Err(e) => {
                    tracing::warn!(
                        sentinel_idx = idx,
                        error = %e,
                        "Sentinel query failed, trying next"
                    );
                    continue;
                }
            }
        }
        Err(anyhow!(
            "All Sentinels unreachable - cannot discover master"
        ))
    }

    /// Query a Sentinel node for the current master address
    async fn query_master(&self, sentinel: &Client) -> Result<String> {
        let mut conn = sentinel.get_async_connection().await?;

        // Authenticate with Sentinel if password is configured
        if let Some(ref password) = self.sentinel_password {
            redis::cmd("AUTH")
                .arg(password)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| anyhow!("Sentinel AUTH failed: {e}"))?;
        }

        // SENTINEL get-master-addr-by-name <master-name>
        let result: Vec<String> = redis::cmd("SENTINEL")
            .arg("get-master-addr-by-name")
            .arg(&self.master_name)
            .query_async(&mut conn)
            .await?;

        if result.len() >= 2 {
            let host = &result[0];
            let port = &result[1];
            Ok(format!("redis://{host}:{port}"))
        } else {
            Err(anyhow!("Invalid Sentinel response: {result:?}"))
        }
    }

    /// Spawn background task to monitor for master failover
    fn spawn_monitor(&self) {
        let sentinel_clients = self.sentinel_clients.clone();
        let master_name = self.master_name.clone();
        let sentinel_password = self.sentinel_password.clone();
        let current_master = self.current_master.clone();
        let db = self.db;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let mut last_master_addr: Option<String> = None;

            loop {
                interval.tick().await;

                // Query Sentinels for current master
                for sentinel in &sentinel_clients {
                    if let Ok(master_addr) =
                        Self::query_master_static(sentinel, &master_name, sentinel_password.as_deref()).await
                    {
                        // Check if master changed (failover occurred)
                        if last_master_addr.as_ref() != Some(&master_addr) {
                            tracing::warn!(
                                old_master = ?last_master_addr,
                                new_master = %master_addr,
                                "Redis master changed - failover detected"
                            );

                            // Update connection to new master
                            let master_url = if db > 0 {
                                format!("{master_addr}/{db}")
                            } else {
                                master_addr.clone()
                            };

                            if let Ok(new_client) = Client::open(master_url.as_str()) {
                                *current_master.write().await = Some(new_client);
                                last_master_addr = Some(master_addr);
                                tracing::info!("Reconnected to new Redis master");
                            }
                        }
                        break;
                    }
                }
            }
        });
    }

    /// Static version of query_master for use in spawned task
    async fn query_master_static(
        sentinel: &Client,
        master_name: &str,
        sentinel_password: Option<&str>,
    ) -> Result<String> {
        let mut conn = sentinel.get_async_connection().await?;

        // Authenticate with Sentinel if password is configured
        if let Some(password) = sentinel_password {
            redis::cmd("AUTH")
                .arg(password)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| anyhow!("Sentinel AUTH failed: {e}"))?;
        }

        let result: Vec<String> = redis::cmd("SENTINEL")
            .arg("get-master-addr-by-name")
            .arg(master_name)
            .query_async(&mut conn)
            .await?;

        if result.len() >= 2 {
            Ok(format!("redis://{}:{}", result[0], result[1]))
        } else {
            Err(anyhow!("Invalid Sentinel response"))
        }
    }

    /// Get a connection to the current master
    ///
    /// If the connection fails, attempts to rediscover the master
    pub async fn get_connection(&self) -> Result<MultiplexedConnection> {
        let master = self.current_master.read().await;
        match master.as_ref() {
            Some(client) => match client.get_multiplexed_tokio_connection().await {
                Ok(conn) => Ok(conn),
                Err(e) => {
                    drop(master);
                    tracing::warn!(error = %e, "Failed to connect to master, rediscovering");
                    self.discover_master().await?;
                    Box::pin(self.get_connection()).await
                }
            },
            None => {
                drop(master);
                self.discover_master().await?;
                Box::pin(self.get_connection()).await
            }
        }
    }
}

// Made with Bob
