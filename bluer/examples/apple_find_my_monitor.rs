//! Monitor for devices advertising Apple Find My data.

use bluer::adv_mon::{AdvertisementMonitor, AdvertisementMonitorEvent, Pattern, Type};
use env_logger;
use futures::StreamExt;

#[tokio::main(flavor = "current_thread")]
async fn main() -> bluer::Result<()> {
    env_logger::init();
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let monitor = AdvertisementMonitor {
        monitor_type: Type::OrPatterns,
        patterns: Some(vec![Pattern {
            start_position: 0,
            ad_data_type: 0xff,
            content_of_pattern: vec![0x4c, 0x00, 0x12],
        }]),
        ..AdvertisementMonitor::default()
    };

    let mut handle = adapter.register_advertisement_monitor(monitor).await?;

    while let Some(event) = handle.next().await {
        match event {
            AdvertisementMonitorEvent::DeviceFound(a) => println!("Found: {}", a),
            AdvertisementMonitorEvent::DeviceLost(a) => println!("Lost: {}", a),
        }
    }

    Ok(())
}
