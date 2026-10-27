# Original Pi Zero W: DPI113 and startup profile

This optional appliance profile contains the exact application source changes and final init/configuration behavior tested on an original Raspberry Pi Zero W (ARM1176/ARMv6, 512 MB). The branch starts at aa-proxy-rs v1.1.0, commit `771f0286cfb23b7ea8fcb5376a3e965ad16fff83`; it does not merge later upstream releases. Upstream defaults outside this optional overlay remain unchanged.

## What is included

The focused commits fix non-UTF-8 vendor names that intermittently prevented the DPI rewrite; avoid unnecessary Wi-Fi probes and repeated config generation; add a small shared configuration helper; prepare immutable rustls configs and first-use entropy during phone Wi-Fi association; omit unused legacy MTP resources in direct mode; and overlap D-Bus/config generation with a barrier before Bluetooth. TLS sessions and randomness stay fresh. Certificate and entropy policy is unchanged.

`config.example.toml` reproduces the final settings with a placeholder Wi-Fi password. DPI113 is the chosen readability/layout compromise for the tested head unit; it is not a universal mathematical optimum. The profile uses MITM/rustls, direct USB, quick reconnect, 2.4 GHz/channel11 and US radio settings. Set the country and Wi-Fi credentials appropriately for your device. Channel11 has no guaranteed immunity to Bluetooth, toll or traffic-light interference.

The final profile disables SSH, web UI, OTA startup, application log persistence, panic-report files, packet/debug dumps, statistics and optional companion/vendor/display features. Boot profiling and its final sync are absent. Basic OS logs remain in tmpfs. Built-in diagnostic code stays compiled into the tested executable; daemon file/console output is discarded by this profile. To troubleshoot later, restore logging/management deliberately rather than resetting phone pairing.

## Build and install scope

Build with the matching existing Buildroot ARMv6 hard-float sysroot and shipped OpenSSL libraries:

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build --locked --release --target arm-unknown-linux-gnueabihf \
  --no-default-features --bin aa-proxy-rs --bin aa-proxy-config
```

Configure the target linker/OpenSSL sysroot for that toolchain. The generic Rust target name does not by itself guarantee compatibility with every Pi/OS ABI; the tested binaries used the matching official rpi0w image toolchain. No kernel or Buildroot rebuild was needed for this experiment.

Install both executables into `/usr/bin` in **both existing A/B root slots**. `overlay/` is a **merged-root filesystem layout**: its `etc/` tree maps to the userdata `etc/` upper directory in the official image's persistent /etc overlay. Review it before installation on any other image. Do not copy an overlay below a second `/etc/etc` directory. Scripts need root ownership/mode0755 and `S92usb_gadget.in` mode0644.

Review `config.example.toml`, set a new Wi-Fi password, then install it as `/etc/aa-proxy-rs/config.toml` with mode0600. Preserve existing pairing, SSH host keys and valid MITM certificate/key files. This repository includes no device credentials, Bluetooth state, certificate/private-key material or SD image. It does not provision a replacement TLS identity; any existing valid certificate repair remains device-local. Do not replace a working identity with expired example certificates.

The S50 overlay is needed to disable SSH: the pinned upstream `enable_ssh` config field alone is not consulted by the stock init launcher. The S93 overlay redirects daemon output; `logfile=/dev/null` also disables the separate file sink. The D-Bus barrier and accessory setup remain active. Switching from direct to legacy mode after boot requires USB init restart or reboot so the legacy MTP resources exist.

## Validation and limits

On ARM1176 QEMU with the shipped runtime libraries, all six config/TLS tests and three DPI regressions pass. The complete library suite has33 passing tests and one pre-existing disabled album-art fragment assertion failure, also reproduced on the unchanged earlier source. Synthetic DPI tests contain no raw vehicle payloads. TLS tests require `AA_TEST_KEYS_PATH` pointing to a private disposable key fixture; do not commit those files.

Generator integration checks cover identical rendered outputs, mode isolation, explicit/omitted/malformed Wi-Fi settings, custom config paths, content-cache invalidation, fallback and CLI errors. Five fake-hardware USB cases and nine shipped-shell init order/failure cases pass. Offline installation checked filesystems, compared unrelated files and verified complete direct readback. Real config/pairing/certificates remained unchanged during performance trials.

Three cold starts and one intentional disconnect/reconnect with the final source build all connect and rewrite DPI113. Linux service launch changed from4.91–4.99s to4.26–4.30s; cold phone TCP-to-DPI changed from2.03–2.10s to0.76–0.94s. Actual entropy initialization took1.59–1.78s during Wi-Fi wait, removing the prior late scheduler stall.

The TCP listener still starts around7–8s, effectively unchanged. Some loading work appears to move from generation into daemon startup. Phone Bluetooth/Wi-Fi variability can hide the post-TCP gain; the owner did not perceive a dramatic startup improvement. Protocol DPI milestones are not visible-ready timestamps, and a shorter init sequence does not establish equal end-to-end savings. The later logging/SSH cleanup retains those tested binaries but has no separately measured speed benefit. Normal audio/touch behavior was retained by configuration; exhaustive calls/controls and long-term reliability are not established by three trials.

## Recovery

Keep the original working SD recovery outside this repository. To undo only the final diagnostic cleanup, restore the prior config and rcS, restore stock S50/S93 script contents, and leave the tested executables in place. Do not delete merged-overlay paths blindly, because whiteouts can hide the underlying stock files. To undo all application changes, replace both root-slot executables with the previous known-good build and restore the matching /etc templates/scripts. Pairing need not be reset.
