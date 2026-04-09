import logging
import os
import re
import json
import time
import subprocess
import threading
import http.client
import urllib.parse
from threading import Lock, Event

import pwnagotchi.plugins as plugins
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.ui.faces as faces

"""
Ultimate Pwnagotchi Cracking Plugin — fast_dictionary v3.1.0
=============================================================

Combines and improves upon:
  - fast_dictionary / quickdic (aircrack-ng dictionary attack)
  - hashie-clean (hcxpcapngtool pcap→hash conversion + lonely pcap cleanup)
  - Notifications via pwn_notify hub (Discord/ntfy/Telegram/Gotify/Webhook)
  - Fallback to built-in Pushover when pwn_notify is not installed
  - CPU thermal management for Raspberry Pi

Dependencies:
  apt:  aircrack-ng hcxtools (provides hcxpcapngtool)
  pip:  scapy (optional, used as fallback for EAPOL detection)

Install hcxtools (if not already present):
  > sudo apt-get install -y libcurl4-openssl-dev libssl-dev zlib1g-dev
  > git clone https://github.com/ZerBea/hcxtools.git /opt/hcxtools
  > cd /opt/hcxtools && make && sudo make install

Upload wordlists (.txt) to the configured folder (default: /home/pi/wordlists/).
Cracked passwords are stored in:
  - Per-handshake: <handshake>.cracked
  - Central potfile: <handshake_dir>/cracked.potfile  (compatible with display-password)

Config (config.toml) example:
  main.plugins.fast_dictionary.enabled = true
  main.plugins.fast_dictionary.wordlist_folder = "/home/pi/wordlists/"
  main.plugins.fast_dictionary.face = "(·ω·)"
  main.plugins.fast_dictionary.time_per_wordlist = 5          # minutes per wordlist
  main.plugins.fast_dictionary.max_cpu_temp = 70              # °C — pause cracking above this
  main.plugins.fast_dictionary.cool_down_temp = 60            # °C — resume cracking below this
  main.plugins.fast_dictionary.temp_check_interval = 15       # seconds between temp checks
  main.plugins.fast_dictionary.max_cpu_cores = 1              # aircrack -p flag (prevent thermal runaway)
  main.plugins.fast_dictionary.use_simd = ""                  # e.g. "neon" for ARM, "" for auto
  main.plugins.fast_dictionary.delete_lonely_pcaps = true     # remove pcaps that can't produce hashes
  main.plugins.fast_dictionary.batch_conversion_on_start = true
  main.plugins.fast_dictionary.batch_crack_on_epoch = false   # attempt cracking ALL uncracked on each epoch
  main.plugins.fast_dictionary.pushover_token = ""            # Pushover app API token
  main.plugins.fast_dictionary.pushover_user = ""             # Pushover user key
  main.plugins.fast_dictionary.pushover_sound = "cashregister"
  main.plugins.fast_dictionary.pushover_priority = 0          # -2 to 2
"""


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

PLUGIN_NAME = "fast_dictionary"
THERMAL_PATH = "/sys/class/thermal/thermal_zone0/temp"
STATUS_FILE_NAME = ".fast_dictionary_status"  # tracks already-processed pcaps
POTFILE_NAME = "cracked.potfile"
INCOMPLETE_PCAPS_FILE = "/root/.incompletePcaps"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (module-level, no state)
# ─────────────────────────────────────────────────────────────────────────────

def _log(text, level="INFO"):
    """Emit a log line prefixed with the plugin name."""
    fn = {
        "DEBUG":   logging.debug,
        "INFO":    logging.info,
        "WARNING": logging.warning,
        "ERROR":   logging.error,
    }.get(level.upper(), logging.info)
    fn(f"[{PLUGIN_NAME}] {text}")


def _get_cpu_temp():
    """Return the CPU temperature in °C (float), or None on failure."""
    try:
        with open(THERMAL_PATH, "r") as f:
            return float(f.read().strip()) / 1000.0
    except Exception:
        return None


def _tool_available(name):
    """Check whether a CLI tool is available on PATH."""
    try:
        r = subprocess.run(
            ["which", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _install_package(pkg):
    """Attempt to install a Debian package."""
    _log(f"Installing {pkg} …")
    try:
        subprocess.run(
            ["apt-get", "install", "-y", pkg],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
        _log(f"{pkg} installed successfully.")
    except Exception as e:
        _log(f"Failed to install {pkg}: {e}", "ERROR")


def _send_pushover(token, user, title, message, sound="cashregister", priority=0):
    """Send a Pushover notification using only stdlib (no requests dependency)."""
    if not token or not user:
        return False
    try:
        params = urllib.parse.urlencode({
            "token":    token,
            "user":     user,
            "title":    title,
            "message":  message,
            "sound":    sound,
            "priority": str(priority),
        })
        conn = http.client.HTTPSConnection("api.pushover.net", 443, timeout=15)
        conn.request(
            "POST",
            "/1/messages.json",
            params,
            {"Content-type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        ok = resp.status == 200
        conn.close()
        if ok:
            _log("Pushover notification sent.")
        else:
            _log(f"Pushover returned HTTP {resp.status}", "WARNING")
        return ok
    except Exception as e:
        _log(f"Pushover error: {e}", "ERROR")
        return False


def _find_wordlists(folder):
    """Return a sorted list of absolute paths to .txt wordlist files."""
    if not folder or not os.path.isdir(folder):
        _log(f"Wordlist folder not found: {folder}", "WARNING")
        return []
    wl = []
    for f in sorted(os.listdir(folder)):
        full = os.path.join(folder, f)
        if os.path.isfile(full) and f.lower().endswith(".txt"):
            wl.append(full)
    return wl


def _parse_cracked_file(path):
    """Read a .cracked file and return the key, or None."""
    try:
        with open(path, "r") as f:
            content = f.read().strip()
        if content:
            return content
    except Exception:
        pass
    return None


def _extract_key_from_aircrack_output(output):
    """Try to pull the KEY from aircrack-ng stdout."""
    m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output)
    if m:
        return m.group(1)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main Plugin
# ─────────────────────────────────────────────────────────────────────────────

class FastDictionary(plugins.Plugin):
    __author__  = "nothingbutlucas + improved by OGMatrix"
    __version__ = "3.1.0"
    __license__ = "GPL3"
    __description__ = (
        "All-in-one handshake processor: pcap→hash conversion (hashie-clean), "
        "dictionary cracking with thermal throttling, lonely pcap cleanup, "
        "and notifications via pwn_notify hub (or Pushover fallback)."
    )
    __dependencies__ = {
        "apt": ["aircrack-ng"],
    }

    # ── defaults (overridden by config.toml) ────────────────────────────────
    __defaults__ = {
        "enabled":                    False,
        "wordlist_folder":            "/home/pi/wordlists/",
        "face":                       "(·ω·)",
        "time_per_wordlist":          5,
        "max_cpu_temp":               70,
        "cool_down_temp":             60,
        "temp_check_interval":        15,
        "max_cpu_cores":              1,
        "use_simd":                   "",
        "delete_lonely_pcaps":        True,
        "batch_conversion_on_start":  True,
        "batch_crack_on_epoch":       False,
        "pushover_token":             "",
        "pushover_user":              "",
        "pushover_sound":             "cashregister",
        "pushover_priority":          0,
    }

    # ── lifecycle ────────────────────────────────────────────────────────────

    def __init__(self):
        self.lock = Lock()
        self._stop_event = Event()
        self._crack_thread = None

        # tool availability flags (set in on_loaded)
        self._has_aircrack = False
        self._has_hcxpcapngtool = False
        self._needs_aircrack = False
        self._needs_hcxtools = False

        # runtime state
        self._handshake_dir = "/root/handshakes"
        self._status_file = ""
        self._potfile = ""
        self._processed_pcaps = set()  # pcaps we've already attempted
        self._agent = None  # cached agent ref for batch/background threads

        # pwn_notify hub: lazy lookup, cached per session
        self._notify_hub = None       # cached reference (None = not checked yet)
        self._notify_hub_checked = False

    def on_loaded(self):
        _log("Plugin loaded (v3.1.0).")
        self._check_tools()
        # Face is set later when agent becomes available

    def _check_tools(self):
        """Detect installed cracking tools."""
        self._has_aircrack = _tool_available("aircrack-ng")
        self._has_hcxpcapngtool = _tool_available("hcxpcapngtool")

        if self._has_aircrack:
            _log("aircrack-ng found.")
        else:
            _log("aircrack-ng NOT found — will install when internet available.", "WARNING")
            self._needs_aircrack = True

        if self._has_hcxpcapngtool:
            _log("hcxpcapngtool found.")
        else:
            _log("hcxpcapngtool NOT found — hash conversion will be skipped until installed.", "WARNING")
            self._needs_hcxtools = True

    # ── pwnagotchi event hooks ───────────────────────────────────────────────

    def on_config_changed(self, config):
        """Called once config is ready. Kick off batch conversion if enabled."""
        self._handshake_dir = config.get("bettercap", {}).get("handshakes", "/root/handshakes")
        self._status_file = os.path.join(self._handshake_dir, STATUS_FILE_NAME)
        self._potfile = os.path.join(self._handshake_dir, POTFILE_NAME)
        self._load_status()

        if self.options.get("batch_conversion_on_start", True):
            threading.Thread(
                target=self._batch_convert_and_crack,
                name="fd-batch",
                daemon=True,
            ).start()

    def on_internet_available(self, agent):
        """Install missing tools when connectivity is present."""
        self._agent = agent
        if self._needs_aircrack:
            self._update_ui(agent, "Installing aircrack-ng...", faces.UPLOAD)
            _install_package("aircrack-ng")
            self._has_aircrack = _tool_available("aircrack-ng")
            if self._has_aircrack:
                self._needs_aircrack = False
                self._update_ui(agent, "aircrack-ng ready!", faces.HAPPY)
            else:
                self._update_ui(agent, "aircrack-ng install failed!", faces.BROKEN)

    def on_handshake(self, agent, filename, access_point, client_station):
        """Triggered every time bettercap captures a new handshake pcap."""
        self._agent = agent
        _log(f"New handshake captured: {filename}")
        name = os.path.basename(filename)[:18]
        self._update_ui(agent, f"New handshake! {name}", faces.EXCITED)
        # Run in a background thread to avoid blocking the main loop
        threading.Thread(
            target=self._process_single_handshake,
            args=(agent, filename, access_point, client_station),
            name="fd-handshake",
            daemon=True,
        ).start()

    def on_epoch(self, agent, epoch, epoch_data):
        """Optionally re-crack all uncracked handshakes every epoch."""
        self._agent = agent
        if self.options.get("batch_crack_on_epoch", False):
            threading.Thread(
                target=self._batch_convert_and_crack,
                name="fd-epoch-batch",
                daemon=True,
            ).start()

    def on_unload(self):
        """Graceful shutdown."""
        self._stop_event.set()
        self._update_ui(None, "Cracker unloaded", faces.SLEEP)
        _log("Plugin unloaded.")

    # ── UI ───────────────────────────────────────────────────────────────────

    def on_ui_setup(self, ui):
        """Add a status element to the pwnagotchi display."""
        try:
            pos = (0, 95)  # adjust for your display
            ui.add_element(
                "fd_status",
                LabeledValue(
                    color=BLACK,
                    label="CRACK:",
                    value="idle",
                    position=pos,
                    label_font=fonts.Bold,
                    text_font=fonts.Medium,
                ),
            )
        except Exception as e:
            _log(f"UI setup error (non-fatal): {e}", "DEBUG")

    def on_ui_update(self, ui):
        """Called periodically — we don't need to do anything dynamic here."""
        pass

    # ── status tracking ──────────────────────────────────────────────────────

    def _load_status(self):
        """Load the set of pcaps we've already processed."""
        if os.path.isfile(self._status_file):
            try:
                with open(self._status_file, "r") as f:
                    self._processed_pcaps = set(line.strip() for line in f if line.strip())
            except Exception:
                self._processed_pcaps = set()

    def _save_status(self):
        """Persist the set of processed pcaps."""
        try:
            with open(self._status_file, "w") as f:
                f.write("\n".join(sorted(self._processed_pcaps)) + "\n")
        except Exception as e:
            _log(f"Could not write status file: {e}", "ERROR")

    def _mark_processed(self, pcap_path):
        """Mark a pcap as processed so we skip it on future runs."""
        basename = os.path.basename(pcap_path)
        self._processed_pcaps.add(basename)
        self._save_status()

    def _is_processed(self, pcap_path):
        return os.path.basename(pcap_path) in self._processed_pcaps

    # ── thermal management ───────────────────────────────────────────────────

    def _wait_for_cool_cpu(self):
        """Block until CPU temperature drops below cool_down_temp.
        Returns False if stop event was set (meaning we should abort)."""
        max_temp = float(self.options.get("max_cpu_temp", 70))
        cool_temp = float(self.options.get("cool_down_temp", 60))
        interval = int(self.options.get("temp_check_interval", 15))

        temp = _get_cpu_temp()
        if temp is None or temp < max_temp:
            return True  # fine to proceed

        _log(f"CPU at {temp:.1f}°C (limit {max_temp}°C) — pausing crack until {cool_temp}°C …", "WARNING")
        self._update_ui(None, f"Too hot! {temp:.0f}C, cooling...", faces.SLEEP)
        while not self._stop_event.is_set():
            time.sleep(interval)
            temp = _get_cpu_temp()
            if temp is None:
                return True  # sensor gone, just proceed
            if temp <= cool_temp:
                _log(f"CPU cooled to {temp:.1f}°C — resuming.")
                self._update_ui(None, f"Cooled to {temp:.0f}C, go!", faces.AWAKE)
                return True

        return False  # stop event set

    # ── hcxpcapngtool hash conversion (hashie-clean) ─────────────────────────

    def _has_hash_file(self, pcap_path):
        """Return True if .22000 or .16800 already exists for this pcap."""
        base = os.path.splitext(pcap_path)[0]
        return os.path.isfile(base + ".22000") or os.path.isfile(base + ".16800")

    def _is_cracked(self, pcap_path):
        """Return True if a .cracked file with content exists for this pcap."""
        cracked_path = pcap_path + ".cracked"
        if not os.path.isfile(cracked_path):
            # Also check the base-name variant
            cracked_path = os.path.splitext(pcap_path)[0] + ".cracked"
        if os.path.isfile(cracked_path):
            return _parse_cracked_file(cracked_path) is not None
        return False

    def _convert_eapol(self, pcap_path):
        """Use hcxpcapngtool to extract EAPOL hash (.22000)."""
        base = os.path.splitext(pcap_path)[0]
        out = base + ".22000"
        try:
            subprocess.run(
                ["hcxpcapngtool", "-o", out, pcap_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if os.path.isfile(out) and os.path.getsize(out) > 0:
                _log(f"EAPOL hash created: {os.path.basename(out)}", "DEBUG")
                return True
            else:
                # Remove empty file if created
                if os.path.isfile(out):
                    os.remove(out)
                return False
        except Exception as e:
            _log(f"hcxpcapngtool EAPOL error: {e}", "ERROR")
            return False

    def _convert_pmkid(self, pcap_path):
        """Use hcxpcapngtool to extract PMKID hash (.16800)."""
        base = os.path.splitext(pcap_path)[0]
        out = base + ".16800"
        try:
            # Try normal extraction first
            subprocess.run(
                ["hcxpcapngtool", "-k", out, pcap_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if os.path.isfile(out) and os.path.getsize(out) > 0:
                _log(f"PMKID hash created: {os.path.basename(out)}", "DEBUG")
                return True

            # Fallback: raw PMKID dump (may need repair)
            subprocess.run(
                ["hcxpcapngtool", "-K", out, pcap_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if os.path.isfile(out) and os.path.getsize(out) > 0:
                # Attempt SSID repair via tcpdump
                if self._repair_pmkid(pcap_path, out):
                    _log(f"PMKID hash repaired: {os.path.basename(out)}", "DEBUG")
                    return True
                else:
                    os.remove(out)
                    return False
            return False
        except Exception as e:
            _log(f"hcxpcapngtool PMKID error: {e}", "ERROR")
            return False

    def _repair_pmkid(self, pcap_path, pmkid_path):
        """Attempt to repair a raw PMKID hash that's missing the SSID field."""
        try:
            with open(pmkid_path, "r") as f:
                hash_string = f.read().strip()

            if not hash_string:
                return False

            # Extract AP MAC → SSID mapping via tcpdump
            client_strings = []
            try:
                tcpdump_out = subprocess.check_output(
                    "tcpdump -ennr " + pcap_path +
                    ' "(type mgt subtype beacon) || (type mgt subtype probe-resp)"'
                    " 2>/dev/null | sed -E 's/.*BSSID:([0-9a-fA-F:]{17}).*\\((.*)\\).*/\\1\\t\\2/g'",
                    shell=True,
                    timeout=15,
                ).decode("utf-8", errors="replace")

                for line in tcpdump_out.split("\n"):
                    if "\t" in line:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            mac_clean = parts[0].replace(":", "")
                            ssid_hex = parts[1].strip().encode().hex()
                            client_strings.append(f"{mac_clean}:{ssid_hex}")
            except Exception:
                pass

            if not client_strings:
                return False

            # Match AP MAC from hash with tcpdump output
            hash_parts = hash_string.split(":")
            if len(hash_parts) < 2:
                return False
            ap_mac = hash_parts[1]

            for cs in client_strings:
                cs_mac, cs_ssid = cs.split(":", 1)
                if cs_mac.lower() == ap_mac.lower():
                    repaired = hash_string.rstrip("\n") + ":" + cs_ssid
                    repaired_parts = repaired.split(":")
                    if len(repaired_parts) == 4 and not repaired.endswith(":"):
                        with open(pmkid_path, "w") as f:
                            f.write(repaired + "\n")
                        return True
            return False
        except Exception as e:
            _log(f"PMKID repair error: {e}", "ERROR")
            return False

    def _convert_pcap(self, pcap_path):
        """Convert a pcap to crackable hash formats. Returns True if at least one hash created."""
        if not self._has_hcxpcapngtool:
            return False

        got_eapol = self._convert_eapol(pcap_path)
        got_pmkid = self._convert_pmkid(pcap_path)
        return got_eapol or got_pmkid

    # ── EAPOL presence check (fast, no scapy dependency) ─────────────────────

    def _pcap_has_handshake_material(self, pcap_path):
        """Quick check: does the pcap contain EAPOL or enough material?
        Uses tshark/tcpdump if available, falls back to scapy."""
        # Method 1: tshark (fast)
        if _tool_available("tshark"):
            try:
                r = subprocess.run(
                    ["tshark", "-r", pcap_path, "-Y", "eapol", "-c", "1", "-T", "fields", "-e", "frame.number"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.stdout.strip():
                    return True
            except Exception:
                pass

        # Method 2: tcpdump (also fast)
        try:
            r = subprocess.run(
                ["tcpdump", "-r", pcap_path, "-c", "1", "ether proto 0x888e"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                return True
        except Exception:
            pass

        # Method 3: scapy fallback
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_path)
            for pkt in packets:
                if pkt.haslayer("EAPOL"):
                    return True
        except Exception:
            pass

        return False

    # ── aircrack-ng cracking ─────────────────────────────────────────────────

    def _build_aircrack_cmd(self, pcap_path, wordlist_path, bssid=None, ssid=None, cracked_out=None):
        """Build the aircrack-ng command list."""
        cmd = ["aircrack-ng"]

        # SIMD optimization (important for ARM/neon)
        simd = self.options.get("use_simd", "")
        if simd:
            cmd.extend(["--simd", simd])

        # Limit CPU cores to prevent thermal runaway
        cores = int(self.options.get("max_cpu_cores", 1))
        cmd.extend(["-p", str(cores)])

        # Wordlist
        cmd.extend(["-w", wordlist_path])

        # Target identifier
        if bssid:
            cmd.extend(["-b", bssid])
        elif ssid:
            cmd.extend(["-e", ssid])

        # Output cracked key to file
        if cracked_out:
            cmd.extend(["-l", cracked_out])

        # Quiet mode
        cmd.append("-q")

        # Input pcap
        cmd.append(pcap_path)

        return cmd

    def _crack_with_aircrack(self, pcap_path, bssid=None, ssid=None):
        """Run aircrack-ng against a pcap with all configured wordlists.
        Returns (password: str, cracked_file: str) or (None, None)."""
        if not self._has_aircrack:
            self._update_ui(None, "aircrack-ng missing!", faces.BROKEN)
            return None, None

        wl_folder = self.options.get("wordlist_folder", "/usr/share/wordlists/")
        # Normalise trailing slash
        wl_folder = wl_folder.rstrip("/")
        wordlists = _find_wordlists(wl_folder)

        if not wordlists:
            _log("No wordlists found — skipping crack.", "WARNING")
            self._update_ui(None, "No wordlists found!", faces.DEMOTIVATED)
            return None, None

        cracked_out = os.path.splitext(pcap_path)[0] + ".cracked"
        timeout_minutes = int(self.options.get("time_per_wordlist", 5))
        timeout_secs = timeout_minutes * 60
        target_name = ssid or bssid or os.path.basename(pcap_path)[:15]

        for idx, wl in enumerate(wordlists):
            if self._stop_event.is_set():
                return None, None

            # Thermal throttle check
            if not self._wait_for_cool_cpu():
                return None, None

            wl_name = os.path.basename(wl)[:12]
            self._update_ui(
                None,
                f"Cracking {target_name[:10]} [{idx+1}/{len(wordlists)}]",
                faces.INTENSE,
            )
            _log(f"Cracking {os.path.basename(pcap_path)} with {os.path.basename(wl)} …", "DEBUG")

            cmd = self._build_aircrack_cmd(pcap_path, wl, bssid=bssid, ssid=ssid, cracked_out=cracked_out)

            try:
                # Run at low scheduling priority (nice 19, ionice idle)
                full_cmd = ["nice", "-n", "19", "ionice", "-c", "3"] + cmd
                result = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_secs,
                )

                # Check if key was found
                if os.path.isfile(cracked_out):
                    key = _parse_cracked_file(cracked_out)
                    if key:
                        return key, cracked_out

                # Also check stdout as fallback
                key = _extract_key_from_aircrack_output(result.stdout)
                if key:
                    # Write to cracked file if aircrack didn't
                    with open(cracked_out, "w") as f:
                        f.write(key)
                    return key, cracked_out

            except subprocess.TimeoutExpired:
                _log(f"Timeout ({timeout_minutes}m) for {os.path.basename(wl)}", "DEBUG")
                self._update_ui(None, f"Timeout {wl_name}, next...", faces.BORED)
                continue
            except Exception as e:
                _log(f"Aircrack error: {e}", "ERROR")
                self._update_ui(None, f"Crack error!", faces.ANGRY)
                continue

        return None, None

    def _find_targets_in_pcap(self, pcap_path):
        """Extract BSSIDs and SSIDs from a pcap file using aircrack-ng's built-in parser.
        Returns (bssids: list, ssids: list)."""
        bssids = []
        ssids = []

        # Use aircrack-ng to list networks in the pcap
        try:
            r = subprocess.run(
                ["aircrack-ng", pcap_path],
                capture_output=True,
                text=True,
                timeout=15,
            )
            # Parse output for lines with handshake info
            # Format: "  1  AA:BB:CC:DD:EE:FF  NetworkName   WPA (1 handshake)"
            pattern = re.compile(
                r"\s*\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s+"
                r"\((\d+\s+handshake|.*PMKID.*)\)"
            )
            for line in r.stdout.split("\n"):
                m = pattern.search(line)
                if m:
                    bssid = m.group(1).strip()
                    ssid = m.group(2).strip()
                    if bssid and bssid not in bssids:
                        bssids.append(bssid)
                    if ssid and ssid not in ssids:
                        ssids.append(ssid)
        except Exception as e:
            _log(f"Target extraction error: {e}", "DEBUG")

        # Fallback: scapy-based extraction
        if not bssids and not ssids:
            try:
                from scapy.all import rdpcap
                from scapy.layers.dot11 import Dot11, Dot11Elt
                packets = rdpcap(pcap_path)
                for pkt in packets:
                    if pkt.haslayer(Dot11):
                        if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
                            try:
                                ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
                                bssid = pkt[Dot11].addr2
                                if ssid and ssid not in ssids:
                                    ssids.append(ssid)
                                if bssid and bssid not in bssids:
                                    bssids.append(bssid)
                            except Exception:
                                pass
            except Exception:
                pass

        return bssids, ssids

    # ── potfile management ───────────────────────────────────────────────────

    def _record_crack(self, pcap_path, bssid, ssid, password):
        """Record a successful crack to the central potfile."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp}|{bssid or ''}|{ssid or ''}|{password}|{os.path.basename(pcap_path)}\n"
        try:
            with open(self._potfile, "a") as f:
                f.write(entry)
        except Exception as e:
            _log(f"Potfile write error: {e}", "ERROR")

    # ── single handshake processing pipeline ─────────────────────────────────

    def _process_single_handshake(self, agent, filename, access_point, client_station):
        """Full pipeline for a single captured handshake."""
        with self.lock:
            try:
                if not os.path.isfile(filename):
                    _log(f"File not found: {filename}", "WARNING")
                    self._update_ui(agent, "Pcap vanished!", faces.SAD)
                    return

                if self._is_cracked(filename):
                    _log(f"Already cracked: {os.path.basename(filename)}", "DEBUG")
                    self._update_ui(agent, "Already cracked this one!", faces.GRATEFUL)
                    return

                name_short = os.path.basename(filename)[:18]

                # ── Step 1: Hash conversion (hashie-clean) ──
                already_has_hash = self._has_hash_file(filename)
                if not already_has_hash and self._has_hcxpcapngtool:
                    self._update_ui(agent, f"Converting {name_short}", faces.SMART)
                    got_hash = self._convert_pcap(filename)
                    if not got_hash:
                        # Check if there's even EAPOL data
                        has_material = self._pcap_has_handshake_material(filename)
                        if not has_material:
                            _log(f"No handshake material in {os.path.basename(filename)}")
                            self._update_ui(agent, f"Empty pcap, bye!", faces.LONELY)
                            if self.options.get("delete_lonely_pcaps", True):
                                self._delete_lonely_pcap(filename)
                            self._mark_processed(filename)
                            return

                # ── Step 2: Find targets ──
                self._update_ui(agent, f"Scanning {name_short}", faces.LOOK_R)
                bssids, ssids = self._find_targets_in_pcap(filename)
                if not bssids and not ssids:
                    _log(f"No targets found in {os.path.basename(filename)}")
                    self._update_ui(agent, "No targets in pcap", faces.DEMOTIVATED)
                    self._mark_processed(filename)
                    return

                # ── Step 3: Crack ──
                target_name = (ssids[0] if ssids else bssids[0])[:15] if (ssids or bssids) else name_short
                self._update_ui(agent, f"Cracking {target_name}...", faces.INTENSE)

                password = None
                cracked_bssid = None
                cracked_ssid = None

                # Try by BSSID first (more reliable)
                for bssid in bssids:
                    if self._stop_event.is_set():
                        return
                    pw, _ = self._crack_with_aircrack(filename, bssid=bssid)
                    if pw:
                        password = pw
                        cracked_bssid = bssid
                        # Find corresponding SSID
                        if ssids:
                            cracked_ssid = ssids[0]
                        break

                # Fallback: try by SSID
                if not password:
                    for ssid in ssids:
                        if self._stop_event.is_set():
                            return
                        pw, _ = self._crack_with_aircrack(filename, ssid=ssid)
                        if pw:
                            password = pw
                            cracked_ssid = ssid
                            if bssids:
                                cracked_bssid = bssids[0]
                            break

                # ── Step 4: Handle result ──
                if password:
                    display_name = cracked_ssid or cracked_bssid or os.path.basename(filename)
                    _log(f"CRACKED! {display_name} → {password}")
                    self._record_crack(filename, cracked_bssid, cracked_ssid, password)
                    self._update_ui(agent, f"PWN'd {display_name[:15]}!", faces.COOL)

                    # Notify via pwn_notify hub → fallback Pushover
                    self._update_ui(agent, f"Sending alert...", faces.UPLOAD)
                    self._notify_crack(filename, cracked_ssid, cracked_bssid, password)
                    self._update_ui(agent, f"PWN'd {display_name[:15]}!", faces.COOL)
                else:
                    _log(f"Could not crack {os.path.basename(filename)}")
                    self._update_ui(agent, f"No luck: {target_name}", faces.SAD)

                self._mark_processed(filename)

            except Exception as e:
                _log(f"Unexpected error processing handshake: {e}", "ERROR")
                self._update_ui(agent, "Processing error!", faces.ANGRY)

    # ── batch processing ─────────────────────────────────────────────────────

    def _batch_convert_and_crack(self):
        """Process all existing pcaps: convert hashes + attempt cracking."""
        with self.lock:
            if not os.path.isdir(self._handshake_dir):
                return

            pcaps = [
                os.path.join(self._handshake_dir, f)
                for f in os.listdir(self._handshake_dir)
                if f.endswith(".pcap")
            ]

            if not pcaps:
                self._update_ui(None, "No pcaps to process", faces.BORED)
                return

            _log(f"Batch processing {len(pcaps)} pcap files …")
            self._update_ui(None, f"Batch: {len(pcaps)} pcaps...", faces.MOTIVATED)
            lonely = []
            converted = 0
            cracked_count = 0

            for i, pcap in enumerate(pcaps):
                if self._stop_event.is_set():
                    break

                basename = os.path.basename(pcap)
                name_short = basename[:15]

                # Skip already cracked
                if self._is_cracked(pcap):
                    continue

                # ── Hash conversion ──
                has_hash = self._has_hash_file(pcap)
                if not has_hash and self._has_hcxpcapngtool:
                    self._update_ui(None, f"Convert {name_short}", faces.SMART)
                    got = self._convert_pcap(pcap)
                    if got:
                        converted += 1
                        has_hash = True
                    else:
                        # Verify it has handshake material at all
                        if not self._pcap_has_handshake_material(pcap):
                            lonely.append(pcap)
                            continue

                # ── Skip already-attempted pcaps (unless batch_crack_on_epoch) ──
                if self._is_processed(pcap) and not self.options.get("batch_crack_on_epoch", False):
                    continue

                # ── Crack ──
                if self._has_aircrack:
                    bssids, ssids = self._find_targets_in_pcap(pcap)
                    cracked = False
                    target_label = (ssids[0] if ssids else bssids[0])[:12] if (ssids or bssids) else name_short

                    self._update_ui(
                        None,
                        f"Batch {i+1}/{len(pcaps)}: {target_label}",
                        faces.INTENSE,
                    )

                    for bssid in bssids:
                        if self._stop_event.is_set():
                            break
                        pw, _ = self._crack_with_aircrack(pcap, bssid=bssid)
                        if pw:
                            ssid = ssids[0] if ssids else None
                            display_name = ssid or bssid
                            _log(f"BATCH CRACKED: {display_name} → {pw}")
                            self._record_crack(pcap, bssid, ssid, pw)
                            cracked = True
                            cracked_count += 1
                            self._update_ui(None, f"PWN'd {display_name[:15]}!", faces.COOL)
                            self._notify_crack(pcap, ssid, bssid, pw, batch=True)
                            break

                    if not cracked:
                        for ssid in ssids:
                            if self._stop_event.is_set():
                                break
                            pw, _ = self._crack_with_aircrack(pcap, ssid=ssid)
                            if pw:
                                bssid = bssids[0] if bssids else None
                                _log(f"BATCH CRACKED: {ssid} → {pw}")
                                self._record_crack(pcap, bssid, ssid, pw)
                                cracked_count += 1
                                self._update_ui(None, f"PWN'd {ssid[:15]}!", faces.COOL)
                                self._notify_crack(pcap, ssid, bssid, pw, batch=True)
                                break

                self._mark_processed(pcap)

                # Progress logging
                if (i + 1) % 25 == 0 or (i + 1) == len(pcaps):
                    _log(f"Batch progress: {i + 1}/{len(pcaps)}")
                    self._update_ui(
                        None,
                        f"Batch: {i+1}/{len(pcaps)} done",
                        faces.MOTIVATED,
                    )

            # ── Lonely pcap cleanup ──
            if lonely and self.options.get("delete_lonely_pcaps", True):
                _log(f"Removing {len(lonely)} lonely pcaps (no usable handshake material).")
                self._update_ui(None, f"Cleaning {len(lonely)} empty pcaps", faces.LONELY)
                self._write_lonely_locations(lonely)
                for lp in lonely:
                    self._delete_lonely_pcap(lp)
                    self._mark_processed(lp)

            # ── Final summary face ──
            if cracked_count > 0:
                self._update_ui(
                    None,
                    f"Batch done! {cracked_count} cracked!",
                    faces.EXCITED,
                )
            else:
                self._update_ui(
                    None,
                    f"Batch done. {converted} hashes.",
                    faces.HAPPY,
                )

            _log(
                f"Batch complete. Converted: {converted}, "
                f"Cracked: {cracked_count}, Lonely removed: {len(lonely)}"
            )

    # ── lonely pcap handling ─────────────────────────────────────────────────

    def _delete_lonely_pcap(self, pcap_path):
        """Remove a pcap that has no usable handshake material."""
        basename = os.path.basename(pcap_path)
        _log(f"Deleting lonely pcap: {basename}", "DEBUG")
        self._update_ui(None, f"Tossing {basename[:16]}", faces.LONELY)
        try:
            os.remove(pcap_path)
            # Also remove associated empty/broken files
            base = os.path.splitext(pcap_path)[0]
            for ext in (".22000", ".16800"):
                f = base + ext
                if os.path.isfile(f) and os.path.getsize(f) == 0:
                    os.remove(f)
        except Exception as e:
            _log(f"Could not delete {basename}: {e}", "ERROR")

    def _write_lonely_locations(self, lonely_pcaps):
        """Export location data for lonely pcaps (for webgpsmap plugin)."""
        try:
            with open(INCOMPLETE_PCAPS_FILE, "w") as f:
                count_with_gps = 0
                for pcap in lonely_pcaps:
                    basename = os.path.basename(pcap)
                    f.write(basename + "\n")
                    base_noext = os.path.splitext(pcap)[0]
                    for ext in (".gps.json", ".geo.json", ".paw-gps.json"):
                        if os.path.isfile(base_noext + ext):
                            count_with_gps += 1
                            break
                if count_with_gps:
                    _log(f"Found {count_with_gps} GPS locations for lonely networks — check webgpsmap.")
        except Exception as e:
            _log(f"Could not write incomplete pcaps list: {e}", "ERROR")

    # ── notification dispatch (pwn_notify → fallback pushover) ─────────────

    def _get_notify_hub(self):
        """Lazy-lookup pwn_notify plugin. Cached after first successful find."""
        if self._notify_hub is not None:
            return self._notify_hub
        if self._notify_hub_checked:
            return None  # already checked, not found
        try:
            hub = plugins.loaded.get("pwn_notify")
            if hub and hasattr(hub, "send"):
                self._notify_hub = hub
                _log("pwn_notify hub detected — using it for notifications.", "DEBUG")
                return hub
        except Exception:
            pass
        self._notify_hub_checked = True
        return None

    def _notify_crack(self, pcap_path, ssid, bssid, password, batch=False):
        """Send crack notification via pwn_notify (preferred) or built-in Pushover."""
        display_name = ssid or bssid or os.path.basename(pcap_path)
        basename = os.path.basename(pcap_path)
        gps = self._get_gps_for_pcap(pcap_path)

        # ── Try pwn_notify hub first ──
        hub = self._get_notify_hub()
        if hub is not None:
            try:
                hub.send(
                    title=f"{'Batch ' if batch else ''}Cracked: {display_name}",
                    message=f"Password: {password}",
                    event="crack",
                    priority=1,
                    gps=gps,
                    fields={
                        "SSID":     ssid or "N/A",
                        "BSSID":    bssid or "N/A",
                        "Password": password,
                        "File":     basename,
                    },
                )
                return  # hub handled it — done
            except Exception as e:
                _log(f"pwn_notify send failed, falling back to Pushover: {e}", "WARNING")

        # ── Fallback: built-in Pushover ──
        po_token = self.options.get("pushover_token", "")
        po_user = self.options.get("pushover_user", "")
        if not po_token or not po_user:
            return  # no notification backend configured

        _send_pushover(
            token=po_token,
            user=po_user,
            title=f"{'Batch ' if batch else ''}Cracked: {display_name}",
            message=(
                f"Network: {ssid or 'N/A'}\n"
                f"BSSID: {bssid or 'N/A'}\n"
                f"Password: {password}\n"
                f"File: {basename}"
            ),
            sound=self.options.get("pushover_sound", "cashregister"),
            priority=int(self.options.get("pushover_priority", 0)),
        )

    def _get_gps_for_pcap(self, pcap_path):
        """Read GPS sidecar files next to a pcap. Returns dict or None."""
        if not pcap_path:
            return None
        # Try agent session first
        if self._agent is not None:
            try:
                info = self._agent.session()
                g = info.get("gps", {})
                lat, lng = g.get("Latitude", 0), g.get("Longitude", 0)
                if lat != 0 and lng != 0:
                    return {"lat": lat, "lng": lng}
            except Exception:
                pass
        # Try sidecar files
        base = os.path.splitext(pcap_path)[0]
        for ext, lat_key, lng_key in [
            (".gps.json",     "Latitude",  "Longitude"),
            (".paw-gps.json", "lat",       "long"),
        ]:
            gps_file = base + ext
            if os.path.isfile(gps_file):
                try:
                    with open(gps_file, "r") as f:
                        data = json.load(f)
                    la, ln = data.get(lat_key), data.get(lng_key)
                    if la and ln:
                        return {"lat": float(la), "lng": float(ln)}
                except Exception:
                    continue
        # Try geo.json (nested structure)
        geo_file = base + ".geo.json"
        if os.path.isfile(geo_file):
            try:
                with open(geo_file, "r") as f:
                    data = json.load(f)
                loc = data.get("location", {})
                la, ln = loc.get("lat"), loc.get("lng")
                if la and ln:
                    return {"lat": float(la), "lng": float(ln)}
            except Exception:
                pass
        return None

    # ── display helper ───────────────────────────────────────────────────────

    def _update_ui(self, agent, text, face=None):
        """Safely update the pwnagotchi display with status and optional face."""
        # Cache the agent reference so batch/background threads can use it
        if agent is not None:
            self._agent = agent
        target = agent or self._agent
        if target is None:
            return
        try:
            display = target.view()
            display.set("status", text)
            if face is not None:
                display.set("face", face)
            display.update(force=True)
        except Exception:
            pass  # display updates are best-effort
