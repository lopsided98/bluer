//! Bluetooth advertisement monitoring.

use dbus::nonblock::Proxy;
use dbus_crossroads::{Crossroads, IfaceBuilder, IfaceToken};
use pin_project::{pin_project, pinned_drop};
use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use strum::{Display, EnumString};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::{method_call, Adapter, Address, Device, Result, SessionInner, SERVICE_NAME, TIMEOUT};

pub(crate) const MANAGER_INTERFACE: &str = "org.bluez.AdvertisementMonitorManager1";
pub(crate) const ADVERTISEMENT_MONITOR_INTERFACE: &str = "org.bluez.AdvertisementMonitor1";
pub(crate) const ADVERTISEMENT_MONITOR_PREFIX: &str = publish_path!("advertisement_monitor");

/// Determines the type of advertisement monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Display, EnumString)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Type {
    /// Patterns with logic OR applied.
    #[strum(serialize = "or_patterns")]
    OrPatterns,
}

impl Default for Type {
    fn default() -> Self {
        Self::OrPatterns
    }
}

/// An advertisement data pattern, used to filter devices in the advertisement monitor.
#[derive(Clone)]
pub struct Pattern {
    /// The index in an AD data field where the search should start. The
    /// beginning of an AD data field is index 0.
    pub start_position: u8,
    /// Advertising data type to match. See
    /// <https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/> for the
    /// possible allowed values.
    pub ad_data_type: u8,
    /// The value of the pattern. The maximum length of the bytes is 31.
    pub content_of_pattern: Vec<u8>,
}

/// Bluetooth advertisement monitor configuration.
///
/// Specifies the Advertisement Data to be broadcast and some advertising
/// parameters.  Properties which are not present will not be included in the
/// data.  Required advertisement data types will always be included.
/// All UUIDs are 128-bit versions in the API, and 16 or 32-bit
/// versions of the same UUID will be used in the advertising data as appropriate.
///
/// Use [Adapter::register_advertisement_monitor] to register a new
/// advertisement monitor.
#[derive(Default)]
pub struct AdvertisementMonitor {
    /// The type of the monitor.
    pub monitor_type: Type,
    /// Used in conjunction with [rssi_low_timeout](AdvertisementMonitor::rssi_low_timeout) to
    /// determine whether a device becomes out-of-range. Valid range is -127 to 20 (dBm), while 127
    /// indicates unset.
    pub rssi_low_threshold: Option<i16>,
    /// Used in conjunction with [rssi_high_timeout](AdvertisementMonitor::rssi_high_timeout) to
    /// determine whether a device becomes in-range. Valid range is -127 to 20 (dBm), while 127
    /// indicates unset.
    pub rssi_high_threshold: Option<i16>,
    /// The time it takes to consider a device as out-of-range. If this many seconds elapses without
    /// receiving any signal at least as strong as
    /// [rssi_low_threshold](AdvertisementMonitor::rssi_low_threshold), a currently in-range device
    /// will be considered as out-of-range (lost). Valid range is 1 to 300 (seconds), while 0
    /// indicates unset.
    pub rssi_low_timeout: Option<u16>,
    /// The time it takes to consider a device as in-range. If this many seconds elapses while we
    /// continuously receive signals at least as strong as
    /// [rssi_high_threshold](AdvertisementMonitor::rssi_high_threshold), a currently out-of-range
    /// device will be considered as in-range (found). Valid range is 1 to 300 (seconds), while 0
    /// indicates unset.
    pub rssi_high_timeout: Option<u16>,
    /// Grouping rules on how to propagate the received advertisement packets to the client. Valid
    /// range is 0 to 255 while 256 indicates unset.
    ///
    /// The meaning of this field is as follows:
    /// * 0: All advertisement packets from in-range devices would be propagated.
    /// * 255: Only the first advertisement packet of in-range devices would be propagated. If the
    /// device becomes lost, then the first packet when it is found again will also be propagated.
    /// * 1 to 254: Advertisement packets would be grouped into 100ms * N time period. Packets in
    /// the same group will only be reported once, with the RSSI value being averaged out.
    ///
    /// Currently this is unimplemented in user space, so the value is only used to be forwarded to
    /// the kernel.
    pub rssi_sampling_period: Option<u16>,
    /// Advertisement data patterns to match. If [monitor_type](AdvertisementMonitor::monitor_type)
    /// is set to [Type::OrPatterns], then this field must be defined and have at least one entry in
    /// the array.
    pub patterns: Option<Vec<Pattern>>,
    #[doc(hidden)]
    pub _non_exhaustive: (),
}

pub(crate) struct RegisteredAdvertisementMonitor {
    a: AdvertisementMonitor,
    event_tx: mpsc::Sender<AdvertisementMonitorEvent>,
    release_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl RegisteredAdvertisementMonitor {
    pub(crate) fn new(
        advertisement_monitor: AdvertisementMonitor, event_tx: mpsc::Sender<AdvertisementMonitorEvent>,
        release_tx: oneshot::Sender<()>,
    ) -> Self {
        Self { a: advertisement_monitor, event_tx, release_tx: Mutex::new(Some(release_tx)) }
    }

    pub(crate) fn register_interface(cr: &mut Crossroads) -> IfaceToken<Arc<Self>> {
        cr.register(ADVERTISEMENT_MONITOR_INTERFACE, |ib: &mut IfaceBuilder<Arc<Self>>| {
            cr_property!(ib, "Type", la => {
                Some(la.a.monitor_type.to_string())
            });
            cr_property!(ib, "RSSILowThreshold", la => {
                la.a.rssi_low_threshold
            });
            cr_property!(ib, "RSSIHighThreshold", la => {
                la.a.rssi_high_threshold
            });
            cr_property!(ib, "RSSILowTimeout", la => {
                la.a.rssi_low_timeout
            });
            cr_property!(ib, "RSSIHighTimeout", la => {
                la.a.rssi_high_timeout
            });
            cr_property!(ib, "RSSISamplingPeriod", la => {
                la.a.rssi_sampling_period
            });
            cr_property!(ib, "Patterns", la => {
                la.a.patterns.as_ref().map(|patterns: &Vec<Pattern>| {
                    patterns
                        .iter()
                        .map(|p| (p.start_position, p.ad_data_type, p.content_of_pattern.clone()))
                        .collect::<Vec<_>>()
                })
            });
            ib.method_with_cr_async("Release", (), (), |ctx, cr, (): ()| {
                method_call(ctx, cr, |reg: Arc<Self>| async move {
                    if let Some(release_tx) = std::mem::replace(&mut *reg.release_tx.lock().await, None) {
                        let _ = release_tx.send(());
                    }
                    Ok(())
                })
            });
            ib.method_with_cr_async("Activate", (), (), |ctx, cr, (): ()| {
                method_call(ctx, cr, |_: Arc<Self>| async move { Ok(()) })
            });
            ib.method_with_cr_async(
                "DeviceFound",
                ("device",),
                (),
                |ctx, cr, (device_path,): (dbus::Path<'static>,)| {
                    method_call(ctx, cr, |reg: Arc<Self>| async move {
                        if let Some((_, device)) = Device::parse_dbus_path(&device_path) {
                            let _ = reg.event_tx.send(AdvertisementMonitorEvent::DeviceFound(device)).await;
                        } else {
                            log::error!("Cannot parse device path: {}", &device_path);
                        }
                        Ok(())
                    })
                },
            );
            ib.method_with_cr_async(
                "DeviceLost",
                ("device",),
                (),
                |ctx, cr, (device_path,): (dbus::Path<'static>,)| {
                    method_call(ctx, cr, |reg: Arc<Self>| async move {
                        if let Some((_, device)) = Device::parse_dbus_path(&device_path) {
                            let _ = reg.event_tx.send(AdvertisementMonitorEvent::DeviceLost(device)).await;
                        } else {
                            log::error!("Cannot parse device path: {}", &device_path);
                        }
                        Ok(())
                    })
                },
            );
        })
    }

    pub(crate) async fn register(
        self, inner: Arc<SessionInner>, adapter_name: Arc<String>,
        event_rx: mpsc::Receiver<AdvertisementMonitorEvent>, release_rx: oneshot::Receiver<()>,
    ) -> Result<AdvertisementMonitorHandle> {
        let root_path = dbus::Path::new(ADVERTISEMENT_MONITOR_PREFIX).unwrap();
        let name =
            dbus::Path::new(format!("{}/{}", ADVERTISEMENT_MONITOR_PREFIX, Uuid::new_v4().as_simple())).unwrap();
        log::trace!("Starting advertisement monitor at {}", &name);

        {
            let mut cr = inner.crossroads.lock().await;
            let om = cr.object_manager();
            cr.insert(root_path.clone(), &[om], ());
            cr.insert(name.clone(), &[inner.advertisement_monitor_token], Arc::new(self));
        }

        log::trace!("Registering advertisement monitor root at {}", &root_path);
        let proxy =
            Proxy::new(SERVICE_NAME, Adapter::dbus_path(&*adapter_name)?, TIMEOUT, inner.connection.clone());
        proxy.method_call(MANAGER_INTERFACE, "RegisterMonitor", (root_path.clone(),)).await?;

        let (drop_tx, drop_rx) = oneshot::channel();
        let unreg_name = name.clone();
        tokio::spawn(async move {
            let _ = tokio::select! {
                _ = drop_rx => {},
                _ = release_rx => {}
            };

            log::trace!("Unregistering advertisement monitor root at {}", &root_path);
            let _: std::result::Result<(), dbus::Error> =
                proxy.method_call(MANAGER_INTERFACE, "UnregisterMonitor", (root_path,)).await;

            log::trace!("Unpublishing advertisement at {}", &unreg_name);
            let mut cr = inner.crossroads.lock().await;
            let _: Option<Self> = cr.remove(&unreg_name);
        });

        Ok(AdvertisementMonitorHandle { name, event_rx: ReceiverStream::new(event_rx), _drop_tx: drop_tx })
    }
}

/// Advertisement monitor event.
#[derive(Clone, Debug)]
pub enum AdvertisementMonitorEvent {
    /// Bluetooth device with specified address was found.
    DeviceFound(Address),
    /// Bluetooth device with specified address was lost.
    DeviceLost(Address),
}

/// Handle to active Bluetooth advertisement monitor.
///
/// Drop to unregister advertisement monitor.
#[pin_project(PinnedDrop)]
pub struct AdvertisementMonitorHandle {
    name: dbus::Path<'static>,
    #[pin]
    event_rx: ReceiverStream<AdvertisementMonitorEvent>,
    _drop_tx: oneshot::Sender<()>,
}

impl futures::stream::Stream for AdvertisementMonitorHandle {
    type Item = AdvertisementMonitorEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.project().event_rx.poll_next(cx)
    }
}

#[pinned_drop]
impl PinnedDrop for AdvertisementMonitorHandle {
    fn drop(self: Pin<&mut Self>) {
        // required for drop order
    }
}

impl fmt::Debug for AdvertisementMonitorHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AdvertisementMonitorHandle {{ {} }}", &self.name)
    }
}
