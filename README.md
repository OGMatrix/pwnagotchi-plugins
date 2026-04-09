<p align="center">
  <img src="https://raw.githubusercontent.com/jayofelony/pwnagotchi/master/ui/web/static/img/logo.png" alt="pwnagotchi" width="120"/>
</p>

<h1 align="center">pwnagotchi-plugins</h1>
<p align="center">
  A curated collection of production-grade plugins for <a href="https://github.com/jayofelony/pwnagotchi">jayofelony's pwnagotchi</a>.<br/>
  Built for reliability, performance, and interoperability on Raspberry Pi hardware.
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#plugins">Plugins</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#support">Support</a>
</p>

---

## Why These Plugins

Most pwnagotchi plugins were written years ago for evilsocket's original image. They crash on jayofelony's fork with `NonExistentKey` errors, block the main loop with synchronous network calls, and hardcode display detection methods that no longer exist.

This repository provides rewritten alternatives that are tested against jayofelony's v2.9.x image and designed to work together. Every plugin follows these principles:

- **Safe config access** everywhere --- no bare `self.options[]` bracket access that crashes on missing keys
- **Background threading** for all network and CPU-intensive work --- the main pwnagotchi loop is never blocked
- **Lazy initialization** --- backends, tools, and dependencies are only loaded when actually used
- **Inter-plugin communication** --- plugins discover each other at runtime and route data through shared APIs
- **Thermal awareness** --- CPU-intensive operations pause when the Pi overheats and resume after cooldown

---

## Installation

### Method 1: Plugin Repository (recommended)

Add this repository to your `config.toml`:

```toml
main.custom_plugin_repos = [
    "https://github.com/OGMatrix/pwnagotchi-plugins/archive/main.zip",
]
```

Then install and update via the CLI:

```bash
sudo pwnagotchi plugins update
sudo pwnagotchi plugins install pwn_notify
sudo pwnagotchi plugins install fast_dictionary
```

### Method 2: Manual

```bash
cd /usr/local/share/pwnagotchi/custom-plugins/
sudo wget https://raw.githubusercontent.com/OGMatrix/pwnagotchi-plugins/main/pwn_notify.py
sudo wget https://raw.githubusercontent.com/OGMatrix/pwnagotchi-plugins/main/fast_dictionary.py
sudo systemctl restart pwnagotchi
```

### Dependencies

| Dependency | Required by | Install |
|---|---|---|
| `aircrack-ng` | fast_dictionary | `sudo apt install aircrack-ng` |
| `hcxtools` | fast_dictionary (hash conversion) | [Build from source](https://github.com/ZerBea/hcxtools) |

Both plugins are **zero pip-dependency** --- all notification backends, HTTP requests, and GPS handling use Python stdlib only.

---

## Plugins

### pwn_notify --- Universal Notification Hub

A centralized notification service for pwnagotchi. Instead of each plugin implementing its own Pushover/Discord/Telegram code, they route everything through `pwn_notify`. Configure your notification backends once, and every plugin that supports it will use them.

**Supported backends:**

| Backend | Features | API Key Required |
|---|---|---|
| **Pushover** | iOS/Android push, GPS as clickable URL | Yes (free tier available) |
| **Discord** | Rich embeds, event-colored sidebars, field tables, large map images with building-level satellite view | Yes (webhook URL, free) |
| **ntfy** | Phone/desktop/browser push, self-hostable, click-to-map actions | Optional |
| **Telegram** | HTML-formatted messages, location pins, field tables | Yes (free via BotFather) |
| **Gotify** | Self-hosted push server | Yes |
| **Webhook** | Generic JSON POST to any URL (Home Assistant, n8n, IFTTT, Slack) | Depends on target |

**Discord embeds include:**

- Event-specific colors and icons (gold for cracks, green for handshakes, purple for peers)
- Structured fields with contextual icons for SSID, BSSID, encryption type, channel, signal strength
- Full-width signal strength bars with quality labels
- Large satellite map images via configurable providers (OSM, Esri, Geoapify)
- Clickable OpenStreetMap and Google Maps links with exact coordinates
- Handshake count and hostname in the footer

**Map providers for Discord embeds:**

| Provider | View | Pin Marker | API Key | Recommended |
|---|---|---|---|---|
| `osm` | Street | No | No | For offline reliability |
| `esri` | Satellite | No | No | Default, most reliable |
| `geoapify` | Satellite | Yes (red WiFi icon) | Free (3000/day) | Best visual result |

**Inter-plugin API:**

Any plugin can send notifications through the hub without knowing which backends are configured:

```python
import pwnagotchi.plugins as plugins

hub = plugins.loaded.get('pwn_notify')
if hub:
    hub.send(
        title   = "Something happened",
        message = "Details here",
        event   = "crack",             # crack | handshake | peer | system | custom
        priority= 1,                   # -2 (silent) to 2 (emergency)
        gps     = {"lat": 52.5, "lng": 13.4},
        fields  = {"Key": "value"},    # shown as embed fields in Discord
    )
```

Or use the module-level convenience function:

```python
from pwn_notify import notify
notify("Title", "Message", event="handshake")
```

The hub handles rate limiting, deduplication, queueing, and GPS auto-detection internally. Sending plugins do not need to worry about any of that.

---

### fast_dictionary --- Handshake Processor and Cracker

An all-in-one replacement for `quickdic`, `aircrackonly`, `hashie`, and `hashie-clean`. Captures a handshake, converts it to crackable hash formats, runs a dictionary attack, and notifies you if the password is found --- all in one plugin, with thermal throttling to keep the Pi alive.

**What it replaces (and why you should remove them):**

| Old Plugin | Conflict if both run | fast_dictionary equivalent |
|---|---|---|
| `quickdic` / `aircrackonly` | Both hook `on_handshake`, double cracking | Full aircrack-ng pipeline with timeout + wordlist rotation |
| `hashie` / `hashie-clean` | Race condition on pcap conversion + deletion | `hcxpcapngtool` conversion with EAPOL + PMKID + SSID repair |
| `pushover_notify` | Double notifications | Routed through `pwn_notify` hub |

**Pipeline per handshake:**

```
on_handshake fired
    |
    +-- Step 1: hcxpcapngtool converts pcap to .22000 (EAPOL) and .16800 (PMKID)
    |           with SSID repair via tcpdump for broken PMKID hashes
    |
    +-- Step 2: Validate handshake material exists (EAPOL check via tshark/tcpdump/scapy)
    |           Delete lonely pcaps that contain no crackable data
    |
    +-- Step 3: Extract targets (BSSID + SSID) via aircrack-ng parser, scapy fallback
    |
    +-- Step 4: Crack with aircrack-ng against each wordlist
    |           - nice -n 19 / ionice -c 3 (lowest scheduling priority)
    |           - -p 1 (single core, configurable)
    |           - --simd=neon (ARM optimization, configurable)
    |           - Thermal throttle: pause at 70C, resume at 60C
    |           - Per-wordlist timeout (default 5 minutes)
    |
    +-- Step 5: If cracked -> save to .cracked file + central potfile
    |           Notify via pwn_notify hub (or built-in Pushover fallback)
    |
    +-- Display: face + status updates at every stage
```

**Notification routing:**

```
fast_dictionary cracks a password
    |
    +-- pwn_notify loaded?
    |     YES -> hub.send(event="crack", gps, fields{SSID, BSSID, Password})
    |            -> Discord, ntfy, Telegram, Pushover, etc.
    |
    +-- NO hub?
          +-- pushover_token configured in fast_dictionary?
          |     YES -> built-in Pushover via stdlib
          +-- NO -> silent (cracking still works, just no notification)
```

`pwn_notify` is **not required** for fast_dictionary to function. Cracking, hash conversion, and potfile management work identically without it. But if you install it, you get multi-backend notifications (Discord embeds with map, ntfy push, Telegram, etc.) instead of Pushover-only.

**Display faces:**

The plugin updates the pwnagotchi's face at every stage of processing:

| Face | Status | Meaning |
|---|---|---|
| EXCITED | `New handshake! MyNetwork` | Fresh pcap arrived |
| SMART | `Converting MyNetwork` | Running hcxpcapngtool |
| LOOK_R | `Scanning MyNetwork` | Extracting targets |
| INTENSE | `Cracking MyNet [2/5]` | Aircrack running against wordlist 2 of 5 |
| COOL | `PWN'd MyNetwork!` | Password found |
| SAD | `No luck: MyNetwork` | All wordlists exhausted |
| SLEEP | `Too hot! 72C, cooling...` | Thermal throttle active |
| AWAKE | `Cooled to 58C, go!` | Resumed after cooldown |
| LONELY | `Tossing empty.pcap` | Deleting pcap with no handshake material |
| BORED | `Timeout rockyou, next...` | Wordlist hit time limit |

---

## Configuration

Add the following to `/etc/pwnagotchi/config.toml`. Only enable the notification backends you actually use.

```toml
# ── pwn_notify ──────────────────────────────────────────────

[main.plugins.pwn_notify]
enabled          = true
rate_limit       = 10        # min seconds between sends per backend
dedup_window     = 300       # suppress identical messages within 5 minutes
queue_size       = 100
include_hostname = true
include_gps      = true

# Enable one or more backends below.

[main.plugins.pwn_notify.discord]
enabled      = true
webhook_url  = "https://discord.com/api/webhooks/YOUR/WEBHOOK"
username     = "Pwnagotchi"
map_provider = "esri"         # "osm" | "esri" | "geoapify"
map_api_key  = ""             # only needed for geoapify
map_zoom     = 14
events       = ["crack", "handshake", "peer", "system"]

[main.plugins.pwn_notify.pushover]
enabled = false
token   = ""
user    = ""
sound   = "cashregister"
events  = ["crack", "handshake"]

[main.plugins.pwn_notify.ntfy]
enabled = false
url     = "https://ntfy.sh"
topic   = ""
token   = ""
events  = ["crack", "handshake"]

[main.plugins.pwn_notify.telegram]
enabled = false
token   = ""
chat_id = ""
events  = ["crack"]

[main.plugins.pwn_notify.gotify]
enabled = false
url     = ""
token   = ""
events  = ["crack", "system"]

[main.plugins.pwn_notify.webhook]
enabled = false
url     = ""
method  = "POST"
headers = '{}'
events  = ["crack", "handshake"]


# ── fast_dictionary ─────────────────────────────────────────

[main.plugins.fast_dictionary]
enabled               = true
wordlist_folder        = "/usr/share/wordlists/"
time_per_wordlist      = 5        # minutes
max_cpu_cores          = 1
max_cpu_temp           = 70       # pause cracking above this (Celsius)
cool_down_temp         = 60       # resume below this
temp_check_interval    = 15       # seconds between temperature reads
use_simd               = ""       # "neon" for ARM, "" for auto-detect
delete_lonely_pcaps    = true
batch_conversion_on_start = true
batch_crack_on_epoch   = false

# Fallback Pushover (only used when pwn_notify is NOT installed)
pushover_token    = ""
pushover_user     = ""
pushover_sound    = "cashregister"
pushover_priority = 0
```

---

## Plugin Compatibility

If you install these plugins, remove the old versions to avoid conflicts:

| Remove | Reason |
|---|---|
| `quickdic.py` | Replaced by fast_dictionary |
| `aircrackonly.py` | Replaced by fast_dictionary |
| `hashie.py` | Replaced by fast_dictionary |
| `hashieclean.py` | Replaced by fast_dictionary |
| `pushover_notify.py` | Replaced by pwn_notify |
| `discord.py` (notification) | Replaced by pwn_notify |

```bash
# Remove conflicting plugins
cd /usr/local/share/pwnagotchi/custom-plugins/
sudo rm -f quickdic.py aircrackonly.py hashie.py hashieclean.py pushover_notify.py
sudo systemctl restart pwnagotchi
```

---

## Credits

**fast_dictionary** is based on:
- [quickdic.py](https://github.com/evilsocket/pwnagotchi-plugins-contrib/blob/master/quickdic.py) by pwnagotchi@rossmarks.uk --- original dictionary attack plugin
- [fast_dictionary.py](https://github.com/nothingbutlucas/pwnagotchi_fast_dictionary) by nothingbutlucas --- improved wordlist handling and display-password compatibility
- [hashie-clean](https://github.com/arturandre/pwnagotchi-beacon-plugins/blob/main/hashieclean.py) by Artur Oliveira --- pcap-to-hash conversion with lonely pcap cleanup
- [hashie.py](https://github.com/evilsocket/pwnagotchi-plugins-contrib/blob/master/hashie.py) by junohea --- original hcxpcaptool integration
- [better_quickdic.py](https://github.com/xfox64x/pwnagotchi_plugins/blob/master/quickdic/quickdic.py) by xfox64x --- single-core CPU limiting, status file tracking

**What changed from the originals:**
- Fixed `os.listdir()` called without the wordlist folder path (original never found wordlists unless CWD matched)
- Fixed `has_cracked()` looking for "KEY FOUND" in the `-l` output file (aircrack only writes the raw key)
- Replaced `shell=True` with list-based subprocess calls (eliminated shell injection via SSID/filenames with special characters)
- Added `hcxpcapngtool` hash conversion pipeline from hashie-clean (EAPOL .22000, PMKID .16800, SSID repair)
- Added thermal throttling with configurable temperature limits
- Added `nice -n 19` / `ionice -c 3` for lowest scheduling priority
- Added `--simd` support for ARM NEON optimization
- Added per-pcap status tracking to avoid redundant work across reboots
- Added background threading so `on_handshake` never blocks the main loop
- Added pwnagotchi face updates at every processing stage
- Added notification routing through pwn_notify with built-in Pushover fallback
- Merged all functionality into a single plugin file (was previously 4 separate plugins)

**pwn_notify** is a new plugin built for this repository. It was designed as a shared notification infrastructure so that individual plugins do not each need to implement their own HTTP clients, rate limiting, deduplication, and backend-specific formatting.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **One plugin per file.** Each plugin is a single `.py` file with no subdirectories.
2. **No pip dependencies.** Use Python stdlib only. The Pi Zero has limited storage and no reliable internet during operation.
3. **Safe config access.** Use `self.options.get("key", default)` wrapped in try/except, never `self.options["key"]`. Jayofelony's pwnagotchi uses tomlkit, which throws `NonExistentKey` instead of `KeyError`.
4. **No blocking in hooks.** Any operation that takes more than 100ms (network, subprocess, file I/O on large datasets) must run in a daemon thread.
5. **Display detection.** Wrap `ui.is_waveshare_v2()` and similar calls in `hasattr()` checks. Jayofelony removed several display methods from the original codebase.
6. **Test on real hardware.** If you do not have a pwnagotchi, note that in your PR.

To submit a plugin:

```bash
git clone https://github.com/OGMatrix/pwnagotchi-plugins.git
cd pwnagotchi-plugins
# Add your plugin as a single .py file
# Add a config example to the README
git checkout -b my-plugin
git add my_plugin.py
git commit -m "Add my_plugin: short description"
git push origin my-plugin
# Open a pull request
```

Include in your PR:
- The plugin `.py` file
- A `config.toml` example block
- A brief description of what it does and what it replaces (if anything)
- Which pwnagotchi image version you tested on

---

## Support

If you find these plugins useful, consider:

- Starring this repository
- Reporting bugs via [GitHub Issues](https://github.com/OGMatrix/pwnagotchi-plugins/issues)
- Submitting improvements via pull request
- Sharing your config and setup in [Discussions](https://github.com/OGMatrix/pwnagotchi-plugins/discussions)

For questions about pwnagotchi itself (not these plugins), refer to the [jayofelony wiki](https://github.com/jayofelony/pwnagotchi/wiki).

---

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
