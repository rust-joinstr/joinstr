use std::{fmt::Debug, str::FromStr, time::Duration};

use simple_nostr_client::nostr::event::{Event, EventBuilder, EventId};
use simple_nostr_client::nostr::key::PublicKey;
use simple_nostr_client::nostr::Keys;
use simple_nostr_client::{WsClient, WsClientBuilder};

use crate::nostr::{error::Error, Pool, PoolMessage};

/// How long to wait for a relay to `OK` a registration event before giving up.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);

/// How many times to (re)build a fresh circuit and try an isolated send before
/// giving up. Each attempt is a different tor circuit.
const ISOLATED_SEND_ATTEMPTS: usize = 3;

#[derive(Default)]
pub struct NostrClient {
    client: Option<WsClient>,
    builder: Option<WsClientBuilder>,
    pub name: String,
}

impl Debug for NostrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClient")
            .field("name", &self.name)
            .finish()
    }
}

impl NostrClient {
    /// Create a new nostr client.
    ///
    /// # Arguments
    /// * `name` - Name of the [`NostrClient`] instance (use for debug logs), can
    ///   be an empty &str.
    pub fn new(name: &str) -> NostrClient {
        NostrClient {
            name: name.into(),
            builder: Some(WsClient::new()),
            ..Default::default()
        }
    }

    /// Add a nostr relay url to [`NostrClient::relays`]
    ///
    /// # Errors
    ///
    /// This function will return an error if the client is already connected
    ///   to some relays.
    pub fn relay(mut self, url: String) -> Result<Self, Error> {
        if let Some(builder) = self.builder.as_mut() {
            builder.set_relay(url);
            Ok(self)
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    /// Route this client through a SOCKS5 proxy (`host:port`), e.g. a local Tor
    /// port. `None` connects directly.
    pub fn proxy(mut self, proxy: Option<String>) -> Result<Self, Error> {
        if let Some(builder) = self.builder.as_mut() {
            builder.set_proxy(proxy);
            Ok(self)
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    /// Set the nostr key pair of this client.
    ///
    /// # Errors
    ///
    /// This function will return an error if the client is already
    ///   connected to some relays.
    pub fn keys(mut self, keys: Keys) -> Result<Self, Error> {
        if let Some(builder) = self.builder.as_mut() {
            builder.set_keys(keys);
            Ok(self)
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    /// Returns the relay url if available
    pub fn get_relay(&self) -> Option<String> {
        self.client.as_ref().map(|client| client.get_relay())
    }

    /// Connect to nostr relays defined in [`NostrClient::relays`].
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - no nostr keypair have been set.
    ///   - adding a relay fails
    ///   - suscribing to NIP04 Dms fails
    pub fn connect_nostr(&mut self) -> Result<(), Error> {
        if let Some(builder) = self.builder.take() {
            let mut client = builder.connect()?;
            client.subscribe_dm()?;
            self.client = Some(client);
            Ok(())
        } else {
            Err(Error::SyncClientBuilderMissing)
        }
    }

    /// Utility function, will error if the client is not connected.
    pub fn is_connected(&self) -> Result<(), Error> {
        if let Some(client) = &self.client {
            client.is_connected().map_err(|_| Error::NotConnected)
        } else {
            Err(Error::NotConnected)
        }
    }

    /// Returns a ref to [`NostrClient::client`]
    ///
    /// # Errors
    ///
    /// This function will return an error if not connected.
    pub fn client(&mut self) -> Result<&mut WsClient, Error> {
        self.client.as_mut().ok_or(Error::NotConnected)
    }

    /// Returns a ref to [`NostrClient::keys`]
    ///
    /// # Errors
    ///
    /// This function will return an error if the keypair has
    ///   not been set.
    pub fn get_keys(&self) -> Result<&Keys, Error> {
        if let Some(client) = &self.client {
            Ok(client.get_keys())
        } else if let Some(builder) = &self.builder {
            builder.get_keys().ok_or(Error::KeysMissing)
        } else {
            Err(Error::KeysMissing)
        }
    }

    /// Post a nostr event.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - the client is not connected
    ///   - fail to send event.
    pub fn post_event(&mut self, event: EventBuilder) -> Result<(), Error> {
        self.client()?.post_event(event)?;
        Ok(())
    }

    /// Send a NIP04 encrypted DM
    ///
    /// # Arguments
    /// * `npub` - nostr pubkey of the receiver
    /// * `content` - raw (unencrypted) message content as String
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - the client is not connected
    ///   - the client do not have signing keys
    ///   - encryption of the message fails
    ///   - sending the DM fails
    pub fn send_dm(&mut self, npub: &PublicKey, content: String) -> Result<(), Error> {
        self.client()?.send_dm(content, npub)?;
        Ok(())
    }

    /// Send a [`PoolMessage`] wrapped into a NIP04 encrypted DM
    ///
    /// # Arguments
    /// * `npub` - nostr pubkey of the pool
    /// * `msg` - the PoolMessage to send
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - teh message cannot be serialized into String json payload
    ///   - sending the DM fails
    pub fn send_pool_message(&mut self, npub: &PublicKey, msg: PoolMessage) -> Result<(), Error> {
        let clear_content = msg.to_string()?;
        log::debug!("NostrClient.send_pool_message(): {:#?}", clear_content);
        self.send_dm(npub, clear_content)
    }

    /// Send a pool message over a brand new connection (a fresh SOCKS isolation
    /// token, hence a fresh Tor circuit), wait for the relay `OK`, and return the
    /// event id. Used for output and input registration so the two are posted
    /// from different exit IPs (unlinkable) and neither is silently dropped. This
    /// instance keeps its own connection for receiving; the throwaway one is used
    /// only to publish, then closed.
    pub fn send_pool_message_isolated(
        &self,
        npub: &PublicKey,
        msg: PoolMessage,
        proxy: Option<String>,
    ) -> Result<EventId, Error> {
        let relay = self.get_relay().ok_or(Error::NotConnected)?;
        let keys = self.get_keys()?.clone();
        let content = msg.to_string()?;

        // Each attempt opens a new connection, which draws a new SOCKS isolation
        // token and therefore a different tor circuit. Building a fresh circuit
        // occasionally overshoots the connect budget or picks a dead relay; a
        // retry routes around it on another circuit instead of failing the round.
        let mut last_err = None;
        for attempt in 0..ISOLATED_SEND_ATTEMPTS {
            let result = WsClient::new()
                .relay(relay.clone())
                .proxy(proxy.clone())
                .keys(keys.clone())
                .connect()
                .and_then(|mut c| c.send_dm_confirmed(content.clone(), npub, CONFIRM_TIMEOUT));
            match result {
                Ok(id) => return Ok(id),
                Err(e) => {
                    log::warn!("send_pool_message_isolated attempt {attempt} failed: {e:?}");
                    last_err = Some(e);
                    if attempt + 1 < ISOLATED_SEND_ATTEMPTS {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        Err(last_err.expect("at least one attempt").into())
    }

    /// Subscribe to notifications of NIP04 DMs thatare send tu the client pubkey
    ///
    /// # Errors
    ///
    /// This function will return an error if :
    ///   - the client is not connected
    ///   - the client does not have signing keys
    ///   - subscription fail
    pub async fn subscribe_dm(&mut self) -> Result<(), Error> {
        self.client()?.subscribe_dm()?;
        Ok(())
    }

    /// Subscribe to notifications of NIP04 DMs thatare send tu the client pubkey
    ///
    /// # Arguments
    /// * `back` - the client will not receive notifications for pools that have been initiated
    ///   `back` seconds in the past.
    ///
    /// # Errors
    ///
    /// This function will return an error if :
    ///   - the client is not connected
    ///   - subscription fail
    pub fn subscribe_pools(&mut self, back: u64) -> Result<(), Error> {
        self.client()?.subscribe_pool(back)?;
        Ok(())
    }

    /// Try to poll notifications/events received by the client, will return:
    ///   - Some(event) if there is at list one event is in the channel, in this
    ///     case the message is remode from the channel.
    ///   - None if the channel is empty
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - the client is not connected
    ///   - the channel is closed
    pub fn receive_event(&mut self) -> Result<Option<Event>, Error> {
        let ev = self.client()?.try_receive()?;
        Ok(ev)
    }

    /// Try to poll notifications/events received by the client and parse it as
    ///    a PoolMessage, will return:
    ///    - Some(PoolMessage) if there is a message in the channel
    ///    - None if the channel is empty
    ///
    /// Note: if the message is of type [`PoolMessage::Join`] and the pubkey is not
    ///   specified, we will replace None by the sender pubkey.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - the client is not connected
    ///   - the channel is closed
    ///   - the the received event is not a NIP04
    ///   - the event cannot be parsed as a PoolMessage
    pub fn try_receive_pool_msg(&mut self) -> Result<Option<PoolMessage>, Error> {
        Ok(if let Some(event) = self.client()?.try_receive()? {
            PoolMessage::from_str(&event.content).ok().map(|m| {
                // if the join request does not contain a pubkey to respond to, we respond to
                // sender
                if let PoolMessage::Join(None) = m {
                    PoolMessage::Join(Some(event.pubkey))
                } else {
                    m
                }
            })
        } else {
            None
        })
    }

    /// Try to poll notifications/events received by the client and parse it as
    ///    a Pool, it will return:
    ///    - Some(Pool) for the next event that parses as a Pool
    ///    - None only once the channel is empty
    ///
    /// Events that fail to parse are skipped rather than reported as `None`:
    /// callers drain this with `while let Some(p) = receive_pool_notification()?`,
    /// so returning `None` for an undecodable event would end the loop early and
    /// silently truncate the listing at the first pool this version cannot read.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fails to receive event
    pub fn receive_pool_notification(&mut self) -> Result<Option<Pool>, Error> {
        while let Some(event) = self.client()?.try_receive()? {
            match Pool::try_from(event) {
                Ok(pool) => return Ok(Some(pool)),
                Err(e) => log::warn!(
                    "NostrClient({}).receive_pool_notification(): skipping undecodable pool event: {:?}",
                    self.name,
                    e
                ),
            }
        }
        Ok(None)
    }
}
