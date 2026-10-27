//! Runtime template generation shared by the proxy CLI and the small boot helper.
//!
//! Keeping the executable entry point separate avoids loading the proxy's
//! Bluetooth, TLS, web and async runtime startup paths just to render files.
use crate::config::AppConfig;
use crate::device_info;
use simplelog::*;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const NAME: &str = "<i><bright-black> config-gen: </>";
const HOSTAPD_CONF_IN: &str = "/etc/hostapd.conf.in";
const HOSTAPD_CONF_OUT: &str = "/var/run/hostapd.conf";
const DNSMASQ_CONF_IN: &str = "/etc/dnsmasq.conf.in";
const DNSMASQ_CONF_OUT: &str = "/var/run/dnsmasq.conf";
const INTERFACES_IN: &str = "/etc/network/interfaces.in";
const INTERFACES_OUT: &str = "/var/run/interfaces";
const UMTPRD_CONF_IN: &str = "/etc/umtprd/umtprd.conf.in";
const UMTPRD_CONF_OUT: &str = "/var/run/umtprd.conf";
const GADGET_INIT_IN: &str = "/etc/S92usb_gadget.in";
const GADGET_INIT_OUT: &str = "/var/run/S92usb_gadget";

/// Returns the full device serial number from Device Tree
fn get_serial_number() -> io::Result<String> {
    Ok(
        fs::read_to_string("/sys/firmware/devicetree/base/serial-number")?
            .trim_end_matches(char::from(0))
            .trim()
            .to_string(),
    )
}

fn render_template(template: &str, vars: &[(&str, &str)]) -> String {
    let mut output = template.to_string();
    for (key, value) in vars {
        let placeholder = format!("{{{{{}}}}}", key);
        output = output.replace(&placeholder, value);
    }
    output
}

fn generate_hostapd_conf(config: &AppConfig) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, HOSTAPD_CONF_IN
    );

    // Technically for IEEE802.11g we have to use g but AFAIK b is fine.
    let hostapd_mode = if config.band == "5" || config.band == "6" {
        "a"
    } else {
        "g"
    };

    let template = fs::read_to_string(HOSTAPD_CONF_IN)?;

    // Eventually: For 6 GHz, we will need more options like opclass.
    let rendered = render_template(
        &template,
        &[
            ("HW_MODE", hostapd_mode),
            ("BE_MODE", if config.wifi_version >= 7 { "1" } else { "0" }),
            ("AX_MODE", if config.wifi_version >= 6 { "1" } else { "0" }),
            ("AC_MODE", if config.wifi_version >= 5 { "1" } else { "0" }),
            ("N_MODE", if config.wifi_version >= 4 { "1" } else { "0" }),
            ("COUNTRY_CODE", &config.country_code),
            ("CHANNEL", &config.channel.to_string()),
            ("SSID", &config.ssid),
            ("WPA_PASSPHRASE", &config.wpa_passphrase),
        ],
    );

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, HOSTAPD_CONF_OUT
    );
    fs::write(HOSTAPD_CONF_OUT, rendered)
}

fn generate_network_conf(config: &AppConfig, input: &str, output: &str) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, input
    );

    let template = fs::read_to_string(input)?;
    let rendered = render_template(&template, &[("WLAN_SUBNET", &config.wlan_subnet)]);

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, output
    );
    fs::write(output, rendered)
}

fn generate_usb_strings(input: &str, output: &str) -> std::io::Result<()> {
    info!(
        "{} 🗃️ Generating config from input template: <bold><green>{}</>",
        NAME, input
    );

    let template = fs::read_to_string(input)?;

    let rendered = render_template(
        &template,
        &[
            (
                "MODEL",
                &device_info::get_sbc_model()
                    .map_or(String::new(), |model| format!(" ({})", model)),
            ),
            (
                "SERIAL",
                &get_serial_number().unwrap_or("0123456".to_string()),
            ),
            (
                "FIRMWARE_VER",
                &format!(
                    "{}, git: {}-{}",
                    env!("BUILD_DATE"),
                    env!("GIT_DATE"),
                    env!("GIT_HASH")
                ),
            ),
        ],
    );

    info!(
        "{} 💾 Saving generated file as: <bold><green>{}</>",
        NAME, output
    );
    fs::write(output, rendered)
}

// /run is recreated at every boot. Hashes, rather than mtimes, remain correct
// with the Pi's initially unset wall clock and detect config/template/output edits.
fn write_hostapd_stamp(config_path: &std::path::Path, allow_cache: bool) {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let stamp = "/var/run/aa-proxy-hostapd.sha256";
    if !allow_cache
        || config_path != std::path::Path::new(concat!(crate::base_config_dir!(), "/config.toml"))
    {
        let _ = fs::remove_file(stamp);
        return;
    }
    let result = (|| -> std::io::Result<()> {
        let paths = [
            config_path,
            std::path::Path::new(HOSTAPD_CONF_IN),
            std::path::Path::new(HOSTAPD_CONF_OUT),
        ];
        let mut text = String::new();
        for path in paths {
            let name = path.to_string_lossy();
            if name.contains(['\n', '\\']) {
                return Err(std::io::Error::other("unsupported checksum filename"));
            }
            text.push_str(&format!(
                "{:x}  {}\n",
                Sha256::digest(fs::read(path)?),
                name
            ));
        }
        let tmp = format!("{stamp}.tmp");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        fs::rename(tmp, stamp)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(stamp);
        warn!(
            "{} hostapd checksum cache unavailable: {}; network setup will regenerate",
            NAME, e
        );
    }
}

/// Generate the system templates, optionally including hostapd for a cold boot.
/// The same full AppConfig is used by both executable entry points.
pub fn generate_system_configs(
    config: &AppConfig,
    config_path: &Path,
    include_hostapd: bool,
) -> io::Result<()> {
    generate_usb_strings(UMTPRD_CONF_IN, UMTPRD_CONF_OUT)?;
    generate_network_conf(config, DNSMASQ_CONF_IN, DNSMASQ_CONF_OUT)?;
    generate_network_conf(config, INTERFACES_IN, INTERFACES_OUT)?;
    generate_usb_strings(GADGET_INIT_IN, GADGET_INIT_OUT)?;
    info!(
        "{} 🚀 Making script executable: <bold><green>{}</>",
        NAME, GADGET_INIT_OUT
    );
    let mut perms = fs::metadata(GADGET_INIT_OUT)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(GADGET_INIT_OUT, perms)?;
    if include_hostapd {
        generate_hostapd_config(config, config_path)?;
    }
    Ok(())
}

/// Generate hostapd and maintain its existing per-boot validated checksum cache.
pub fn generate_hostapd_config(config: &AppConfig, config_path: &Path) -> io::Result<()> {
    generate_hostapd_conf(config)?;
    write_hostapd_stamp(config_path, !config.runtime_wifi_defaults_used);
    Ok(())
}
