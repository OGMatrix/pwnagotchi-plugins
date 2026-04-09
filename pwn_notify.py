import logging
import os
import json
import time
import threading
import queue
import math
import http.client
import urllib.parse
import socket
from collections import OrderedDict

import pwnagotchi.plugins as plugins

"""
pwn_notify — Universal Notification Hub for Pwnagotchi (v2.1.0)
================================================================

Zero-dependency notification hub. Other plugins call send() as an API.

Backends (all stdlib):
  Pushover | Discord (rich embeds + map) | ntfy.sh | Telegram | Gotify | Webhook

Inter-Plugin API:
  hub = plugins.loaded.get('pwn_notify')
  if hub:
      hub.send(title="Cracked!", message="pw: hunter2", event="crack",
               priority=1, gps={"lat": 52.5, "lng": 13.4},
               fields={"BSSID": "AA:BB:CC:DD:EE:FF"})

  # Or: from pwn_notify import notify
  # notify("Title", "Message", event="handshake")

Discord map providers (main.plugins.pwn_notify.discord.map_provider):
  "osm"      — OpenStreetMap tiles, no API key, street view (default)
  "esri"     — Esri World Imagery, no API key, satellite view
  "geoapify" — Geoapify static maps, free API key, satellite + pin marker
               Register free at https://myprojects.geoapify.com/ (3000 req/day)
               Set: main.plugins.pwn_notify.discord.map_api_key = "YOUR_KEY"

Config (config.toml):

  main.plugins.pwn_notify.enabled = true
  main.plugins.pwn_notify.rate_limit = 10
  main.plugins.pwn_notify.dedup_window = 300
  main.plugins.pwn_notify.queue_size = 100
  main.plugins.pwn_notify.include_hostname = true
  main.plugins.pwn_notify.include_gps = true

  [main.plugins.pwn_notify.discord]
  enabled      = true
  webhook_url  = "https://discord.com/api/webhooks/..."
  username     = "Pwnagotchi"
  avatar_url   = ""
  map_provider = "osm"        # "osm" | "esri" | "geoapify"
  map_api_key  = ""           # only for geoapify
  map_zoom     = 14           # lower = wider area
  map_width    = 600          # geoapify only
  map_height   = 300          # geoapify only
  events       = ["crack", "handshake", "peer", "system"]

  [main.plugins.pwn_notify.pushover]
  enabled = true
  token   = "APP_TOKEN"
  user    = "USER_KEY"
  sound   = "cashregister"
  events  = ["crack", "handshake", "system"]

  [main.plugins.pwn_notify.ntfy]
  enabled = true
  url     = "https://ntfy.sh"
  topic   = "my-secret-topic"
  token   = ""
  events  = ["crack", "handshake"]

  [main.plugins.pwn_notify.telegram]
  enabled = true
  token   = "BOT_TOKEN"
  chat_id = "CHAT_ID"
  events  = ["crack"]

  [main.plugins.pwn_notify.gotify]
  enabled = true
  url     = "https://gotify.example.com"
  token   = "APP_TOKEN"
  events  = ["crack", "system"]

  [main.plugins.pwn_notify.webhook]
  enabled = true
  url     = "https://example.com/hook"
  method  = "POST"
  headers = '{"Authorization": "Bearer xxx"}'
  events  = ["crack", "handshake"]
"""

PLUGIN_NAME = "pwn_notify"
LOG_PREFIX = f"[{PLUGIN_NAME}]"

# ═══════════════════════════════════════════════════════════════════════════
# EVENT STYLING — colors, emojis, labels per event type
# ═══════════════════════════════════════════════════════════════════════════

_EVENT_STYLE = {
    "crack":     {"color": 0xFFD700, "emoji": "\U0001f513", "label": "Password Cracked"},
    "handshake": {"color": 0x00FF88, "emoji": "\U0001f91d", "label": "Handshake Captured"},
    "peer":      {"color": 0x9B59B6, "emoji": "\U0001f47e", "label": "Peer Detected"},
    "system":    {"color": 0x3498DB, "emoji": "\u2699\ufe0f", "label": "System"},
    "status":    {"color": 0x95A5A6, "emoji": "\U0001f4ca", "label": "Status Update"},
    "custom":    {"color": 0x607D8B, "emoji": "\U0001f4e1", "label": "Notification"},
}

# Field emojis for Discord embeds
_FIELD_EMOJI = {
    "ssid": "\U0001f4f6", "bssid": "\U0001f517", "file": "\U0001f4c1",
    "password": "\U0001f511", "client": "\U0001f4f1", "mac": "\U0001f4f1",
    "name": "\U0001f3f7\ufe0f", "manufacturer": "\U0001f3ed",
    "ap": "\U0001f4e1", "encryption": "\U0001f512", "type": "\U0001f4e5",
    "channel": "\U0001f4fb", "signal": "\U0001f4f6", "vendor": "\U0001f3ed",
    "band": "\U0001f30d",
}

def _log(msg, level="INFO"):
    fn = getattr(logging, level.lower(), logging.info)
    fn(f"{LOG_PREFIX} {msg}")


def _html_escape(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _osm_url(lat, lng):
    return f"https://www.openstreetmap.org/?mlat={lat}&mlon={lng}#map=17/{lat}/{lng}"


def _gmaps_url(lat, lng):
    return f"https://www.google.com/maps?q={lat},{lng}"


def _extract_gps_floats(gps):
    if not gps or not isinstance(gps, dict):
        return None, None
    lat = gps.get("lat") or gps.get("Latitude") or gps.get("latitude")
    lng = gps.get("lng") or gps.get("Longitude") or gps.get("longitude")
    try:
        return float(lat), float(lng)
    except (ValueError, TypeError):
        return None, None


# ═══════════════════════════════════════════════════════════════════════════
# MAP IMAGE URL BUILDERS
# ═══════════════════════════════════════════════════════════════════════════

def _map_url_osm(lat, lng, zoom=14):
    """OpenStreetMap tile — street view, no key, no pin, 256x256."""
    n = 2 ** zoom
    xtile = int((lng + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.log(math.tan(math.radians(lat)) +
                1.0 / math.cos(math.radians(lat))) / math.pi) / 2.0 * n)
    return f"https://tile.openstreetmap.org/{zoom}/{xtile}/{ytile}.png"


def _map_url_esri(lat, lng, zoom=14):
    """Esri World Imagery — satellite, no key, no pin, 256x256."""
    n = 2 ** zoom
    xtile = int((lng + 180.0) / 360.0 * n)
    ytile = int((1.0 - math.log(math.tan(math.radians(lat)) +
                1.0 / math.cos(math.radians(lat))) / math.pi) / 2.0 * n)
    return (f"https://server.arcgisonline.com/ArcGIS/rest/services/"
            f"World_Imagery/MapServer/tile/{zoom}/{ytile}/{xtile}")


def _map_url_geoapify(lat, lng, zoom=14, width=600, height=300, api_key="", style="satellite"):
    """Geoapify static map — satellite + red pin, free key (3000/day)."""
    if not api_key:
        return _map_url_esri(lat, lng, zoom)  # fallback if no key
    marker = f"lonlat:{lng},{lat};color:%23ff3333;size:x-large;type:awesome;icon:wifi"
    return (f"https://maps.geoapify.com/v1/staticmap?"
            f"style={style}&width={width}&height={height}"
            f"&center=lonlat:{lng},{lat}&zoom={zoom}"
            f"&marker={marker}"
            f"&apiKey={api_key}")


def _build_map_url(cfg, lat, lng):
    """Build map image URL based on discord config."""
    provider = cfg.get("map_provider", "osm")
    zoom = int(cfg.get("map_zoom", 14))
    api_key = cfg.get("map_api_key", "")

    if provider == "geoapify" and api_key:
        w = int(cfg.get("map_width", 600))
        h = int(cfg.get("map_height", 300))
        style = cfg.get("map_style", "satellite")
        return _map_url_geoapify(lat, lng, zoom, w, h, api_key, style)
    elif provider == "esri":
        return _map_url_esri(lat, lng, zoom)
    else:
        return _map_url_osm(lat, lng, zoom)


def _http_request(url, method, body, headers, timeout=15):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    try:
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        status = resp.status
        conn.close()
        return status, 200 <= status < 300
    except Exception as e:
        _log(f"HTTP error ({parsed.hostname}): {e}", "ERROR")
        return 0, False


# ═══════════════════════════════════════════════════════════════════════════
# BACKEND SENDERS
# ═══════════════════════════════════════════════════════════════════════════

def _send_pushover(cfg, title, message, priority=0, **kw):
    token = cfg.get("token", "")
    user = cfg.get("user", "")
    if not token or not user:
        return False
    po_prio = max(-2, min(2, int(priority)))
    params = {
        "token": token, "user": user,
        "title": title[:250], "message": message[:1024],
        "priority": str(po_prio), "sound": cfg.get("sound", "pushover"),
    }
    if po_prio == 2:
        params["retry"] = "60"
        params["expire"] = "3600"
    lat, lng = _extract_gps_floats(kw.get("gps"))
    if lat is not None:
        params["url"] = _osm_url(lat, lng)
        params["url_title"] = "View on Map"
    body = urllib.parse.urlencode(params)
    status, ok = _http_request(
        "https://api.pushover.net/1/messages.json", "POST", body,
        {"Content-type": "application/x-www-form-urlencoded"})
    return ok


def _send_discord(cfg, title, message, priority=0, **kw):
    """Discord webhook with rich embeds, event-specific styling, and large map."""
    webhook_url = cfg.get("webhook_url", "")
    if not webhook_url:
        return False

    gps = kw.get("gps")
    fields_dict = kw.get("fields")
    event = kw.get("event", "custom")
    hostname = kw.get("hostname", "")

    # Event-specific styling
    style = _EVENT_STYLE.get(event, _EVENT_STYLE["custom"])

    # ── Build embed ──
    embed = {
        "title":       f"{style['emoji']}  {style['label']}",
        "description": message[:4096],
        "color":       style["color"],
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Footer with hostname
    footer_parts = ["Pwnagotchi"]
    if hostname:
        footer_parts.insert(0, hostname)
    # Count handshakes for footer
    try:
        hs_dir = "/root/handshakes"
        if os.path.isdir(hs_dir):
            hs_count = sum(1 for f in os.listdir(hs_dir) if f.endswith(".pcap"))
            footer_parts.append(f"{hs_count} handshakes")
    except Exception:
        pass
    embed["footer"] = {"text": " \u2022 ".join(footer_parts)}

    # ── Fields with emojis ──
    embed_fields = []
    # Fields that should be full-width (not inline)
    _FULL_WIDTH = {"password", "signal", "file", "location"}
    if fields_dict and isinstance(fields_dict, dict):
        for key, val in list(fields_dict.items())[:20]:
            if not val or val == "N/A":
                continue
            key_lower = key.lower()
            emoji = _FIELD_EMOJI.get(key_lower, "")
            prefix = f"{emoji} " if emoji else ""
            is_inline = key_lower not in _FULL_WIDTH

            if key_lower == "password":
                embed_fields.append({
                    "name": f"\U0001f511 {key}",
                    "value": f"```{val}```",
                    "inline": False,
                })
            elif key_lower == "signal":
                embed_fields.append({
                    "name": f"{prefix}{key}",
                    "value": f"```{val}```",
                    "inline": False,
                })
            else:
                embed_fields.append({
                    "name": f"{prefix}{key}",
                    "value": f"`{val}`" if len(str(val)) < 40 else str(val)[:1024],
                    "inline": is_inline,
                })

    # ── GPS / Map ──
    lat, lng = _extract_gps_floats(gps)
    if lat is not None:
        # Map links field
        embed_fields.append({
            "name": "\U0001f4cd Location",
            "value": (
                f"[OpenStreetMap]({_osm_url(lat, lng)}) \u2022 "
                f"[Google Maps]({_gmaps_url(lat, lng)})\n"
                f"```{lat:.6f}, {lng:.6f}```"
            ),
            "inline": False,
        })
        # Large map IMAGE (not thumbnail)
        map_img = _build_map_url(cfg, lat, lng)
        embed["image"] = {"url": map_img}

    if embed_fields:
        embed["fields"] = embed_fields

    # ── Payload ──
    payload = {"embeds": [embed]}
    username = cfg.get("username", "")
    if username:
        payload["username"] = username
    avatar = cfg.get("avatar_url", "")
    if avatar:
        payload["avatar_url"] = avatar

    body = json.dumps(payload)
    status, _ = _http_request(webhook_url, "POST", body, {"Content-Type": "application/json"})
    return status in (200, 204)


def _send_ntfy(cfg, title, message, priority=0, **kw):
    base_url = cfg.get("url", "https://ntfy.sh").rstrip("/")
    topic = cfg.get("topic", "")
    if not topic:
        return False
    ntfy_prio = {-2: "1", -1: "2", 0: "3", 1: "4", 2: "5"}.get(int(priority), "3")
    event = kw.get("event", "")
    tag_map = {"crack": "key,white_check_mark", "handshake": "handshake,zap",
               "peer": "busts_in_silhouette", "system": "gear", "status": "bar_chart"}
    tags = tag_map.get(event, "robot_face")
    headers = {"Title": title[:250], "Priority": ntfy_prio, "Tags": tags}
    lat, lng = _extract_gps_floats(kw.get("gps"))
    if lat is not None:
        headers["Click"] = _osm_url(lat, lng)
        headers["Actions"] = f"view, Open Map, {_osm_url(lat, lng)}"
    token = cfg.get("token", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    full_url = f"{base_url}/{topic}"
    status, ok = _http_request(full_url, "POST", message.encode("utf-8")[:4096], headers)
    return ok


def _send_telegram(cfg, title, message, priority=0, **kw):
    token = cfg.get("token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        return False
    prio_emoji = {-2: "", -1: "", 0: "", 1: "\u26a0\ufe0f ", 2: "\U0001f6a8 "}.get(int(priority), "")
    text = f"<b>{prio_emoji}{_html_escape(title)}</b>\n\n{_html_escape(message)}"
    fields_dict = kw.get("fields")
    if fields_dict and isinstance(fields_dict, dict):
        for k, v in fields_dict.items():
            if v and v != "N/A":
                text += f"\n<b>{_html_escape(k)}:</b> <code>{_html_escape(v)}</code>"
    lat, lng = _extract_gps_floats(kw.get("gps"))
    if lat is not None:
        text += f'\n\n<a href="{_osm_url(lat, lng)}">View on Map</a>'
    params = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text[:4096],
        "parse_mode": "HTML", "disable_web_page_preview": "false",
    })
    status, ok = _http_request(
        f"https://api.telegram.org/bot{token}/sendMessage", "POST", params,
        {"Content-type": "application/x-www-form-urlencoded"})
    if ok and lat is not None:
        loc_params = urllib.parse.urlencode({"chat_id": chat_id, "latitude": str(lat), "longitude": str(lng)})
        _http_request(
            f"https://api.telegram.org/bot{token}/sendLocation", "POST", loc_params,
            {"Content-type": "application/x-www-form-urlencoded"})
    return ok


def _send_gotify(cfg, title, message, priority=0, **kw):
    base_url = cfg.get("url", "").rstrip("/")
    token = cfg.get("token", "")
    if not base_url or not token:
        return False
    gotify_prio = {-2: 0, -1: 2, 0: 5, 1: 7, 2: 10}.get(int(priority), 5)
    lat, lng = _extract_gps_floats(kw.get("gps"))
    full_msg = message
    if lat is not None:
        full_msg += f"\n\nMap: {_osm_url(lat, lng)}"
    payload = json.dumps({"title": title[:250], "message": full_msg[:4096], "priority": gotify_prio})
    status, ok = _http_request(
        f"{base_url}/message?token={token}", "POST", payload,
        {"Content-Type": "application/json"})
    return ok


def _send_webhook(cfg, title, message, priority=0, **kw):
    url = cfg.get("url", "")
    if not url:
        return False
    method = cfg.get("method", "POST").upper()
    payload = {
        "title": title, "message": message, "priority": priority,
        "event": kw.get("event", ""), "hostname": kw.get("hostname", ""),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    gps = kw.get("gps")
    if gps:
        payload["gps"] = gps
    fields_dict = kw.get("fields")
    if fields_dict:
        payload["fields"] = fields_dict
    headers = {"Content-Type": "application/json"}
    headers_cfg = cfg.get("headers", "")
    if headers_cfg:
        try:
            extra = json.loads(headers_cfg) if isinstance(headers_cfg, str) else headers_cfg
            headers.update(extra)
        except Exception:
            pass
    body = json.dumps(payload)
    _, ok = _http_request(url, method, body, headers)
    return ok


_BACKENDS = {
    "pushover": _send_pushover, "discord": _send_discord,
    "ntfy": _send_ntfy, "telegram": _send_telegram,
    "gotify": _send_gotify, "webhook": _send_webhook,
}


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def notify(title, message, event="custom", priority=0, gps=None, fields=None):
    """Call from any plugin:  from pwn_notify import notify"""
    try:
        plugin = plugins.loaded.get(PLUGIN_NAME)
        if plugin:
            plugin.send(title=title, message=message, event=event,
                        priority=priority, gps=gps, fields=fields)
        else:
            _log("pwn_notify not loaded — notification dropped.", "WARNING")
    except Exception as e:
        _log(f"notify() error: {e}", "ERROR")


# ═══════════════════════════════════════════════════════════════════════════
# PLUGIN CLASS
# ═══════════════════════════════════════════════════════════════════════════

class PwnNotify(plugins.Plugin):
    __author__  = "OGMatrix"
    __version__ = "2.1.0"
    __license__ = "GPL3"
    __description__ = (
        "Universal notification hub — Pushover, Discord (rich embeds + maps), "
        "ntfy, Telegram, Gotify, Webhook. Other plugins use send() as an API."
    )
    __dependencies__ = {}
    __defaults__ = {
        "enabled": False, "rate_limit": 10, "dedup_window": 300,
        "queue_size": 100, "include_hostname": True, "include_gps": True,
    }

    def __init__(self):
        self._queue = None
        self._worker = None
        self._stop = threading.Event()
        self._last_send = {}
        self._dedup_cache = None
        self._hostname = ""
        self._agent = None
        self._active_backends = []
        self._stats = {"sent": 0, "failed": 0, "dropped": 0}

    # ── lifecycle ──────────────────────────────────────────────────────────

    def on_loaded(self):
        _log("Plugin loaded (v2.1.0).")

    def on_config_changed(self, config):
        self._hostname = socket.gethostname()
        self._discover_backends()
        if not self._active_backends:
            _log("No backends configured.", "WARNING")
            return
        _log(f"Active: {', '.join(b[0] for b in self._active_backends)}")
        self._queue = queue.Queue(maxsize=int(self.options.get("queue_size", 100)))
        self._dedup_cache = OrderedDict()
        self._stop.clear()
        self._worker = threading.Thread(target=self._worker_loop, name="pwn-notify", daemon=True)
        self._worker.start()

    def on_unload(self, ui=None):
        self._stop.set()
        _log(f"Unloaded. Stats: {self._stats}")

    def on_ready(self, agent):
        self._agent = agent
        self.send(title="Pwnagotchi Online",
                  message=f"{self._hostname} is ready and scanning.",
                  event="system", priority=-1)

    def on_internet_available(self, agent):
        self._agent = agent

    def on_handshake(self, agent, filename, access_point, client_station):
        self._agent = agent
        gps = self._get_gps(agent, filename)

        # ── Extract AP metadata ──
        ssid = bssid = vendor = encryption = ""
        channel = 0
        rssi = 0
        if isinstance(access_point, dict):
            ssid = access_point.get("hostname", access_point.get("name", ""))
            bssid = access_point.get("mac", "")
            vendor = access_point.get("vendor", "")
            encryption = access_point.get("encryption", "")
            channel = access_point.get("channel", 0) or 0
            rssi = access_point.get("rssi", 0) or 0
        elif isinstance(access_point, str):
            bssid = access_point

        # ── Determine capture type ──
        if client_station is None:
            capture_type = "PMKID"
            client_mac = ""
        elif isinstance(client_station, str):
            if client_station.lower() == "pmkid":
                capture_type = "PMKID"
                client_mac = ""
            else:
                capture_type = "Handshake"
                client_mac = client_station
        elif isinstance(client_station, dict):
            capture_type = "Handshake"
            client_mac = client_station.get("mac", "")
        else:
            capture_type = "Handshake"
            client_mac = ""

        # ── Derive band from channel ──
        band = ""
        if channel:
            try:
                ch = int(channel)
                if 1 <= ch <= 14:
                    band = "2.4 GHz"
                elif ch >= 32:
                    band = "5 GHz"
            except (ValueError, TypeError):
                pass

        # ── Fallback: extract from pcap if AP dict was sparse ──
        if not encryption or not channel:
            try:
                from pwnagotchi.utils import extract_from_pcap, WifiInfo
                pcap_info = extract_from_pcap(filename, [WifiInfo.ENCRYPTION, WifiInfo.CHANNEL, WifiInfo.RSSI])
                if not encryption:
                    encryption = pcap_info.get(WifiInfo.ENCRYPTION, "")
                if not channel:
                    ch = pcap_info.get(WifiInfo.CHANNEL, 0)
                    if ch:
                        channel = ch
                        if 1 <= ch <= 14:
                            band = "2.4 GHz"
                        elif ch >= 32:
                            band = "5 GHz"
                if not rssi:
                    rssi = pcap_info.get(WifiInfo.RSSI, 0) or 0
            except Exception:
                pass  # pcap extraction is best-effort

        # ── Signal strength bar ──
        signal_bar = ""
        if rssi and rssi != 0:
            try:
                r = int(rssi)
                if r >= -50:
                    signal_bar = "\u2588\u2588\u2588\u2588 Excellent"
                elif r >= -60:
                    signal_bar = "\u2588\u2588\u2588\u2591 Good"
                elif r >= -70:
                    signal_bar = "\u2588\u2588\u2591\u2591 Fair"
                elif r >= -80:
                    signal_bar = "\u2588\u2591\u2591\u2591 Weak"
                else:
                    signal_bar = "\u2591\u2591\u2591\u2591 Very Weak"
            except (ValueError, TypeError):
                pass

        # ── Build fields dict ──
        name = ssid or bssid or os.path.basename(filename)
        fields = {}
        if ssid:
            fields["SSID"] = ssid
        if bssid:
            fields["BSSID"] = bssid
        if encryption:
            fields["Encryption"] = encryption
        fields["Type"] = capture_type
        if channel:
            ch_str = str(channel)
            if band:
                ch_str += f" ({band})"
            fields["Channel"] = ch_str
        if signal_bar:
            fields["Signal"] = f"{rssi} dBm  {signal_bar}"
        if vendor:
            fields["Vendor"] = vendor
        if client_mac:
            fields["Client"] = client_mac
        fields["File"] = os.path.basename(filename)

        # ── Build message ──
        msg_parts = [f"Captured {capture_type} from {name}"]
        if bssid and ssid:
            msg_parts[0] += f" ({bssid})"
        if encryption:
            msg_parts.append(f"{encryption}")
        if band:
            msg_parts.append(f"{band}")
        if rssi:
            msg_parts.append(f"{rssi} dBm")

        self.send(
            title=f"{capture_type}: {name}",
            message=" \u2022 ".join(msg_parts),
            event="handshake", priority=0, gps=gps,
            fields=fields,
        )

    def on_peer_detected(self, agent, peer):
        self._agent = agent
        name = peer.get("name", "unknown") if isinstance(peer, dict) else str(peer)
        self.send(title=f"Peer: {name}", message="A fellow pwnagotchi is nearby!",
                  event="peer", priority=-1)

    # ── webhook UI for stats ─────────────────────────────────────────────

    def on_webhook(self, path, request):
        import json as _json
        stats = {**self._stats, "backends": [b[0] for b in self._active_backends],
                 "queue_depth": self._queue.qsize() if self._queue else 0}
        return _json.dumps(stats, indent=2)

    # ── public API ─────────────────────────────────────────────────────────

    def send(self, title, message, event="custom", priority=0,
             gps=None, fields=None, backends=None):
        """Public API for other plugins."""
        if self._queue is None:
            self._stats["dropped"] += 1
            return
        if gps is None and self.options.get("include_gps", True):
            gps = self._get_gps(self._agent)
        payload = {
            "title": title, "message": message, "event": event,
            "priority": priority, "gps": gps, "fields": fields,
            "backends": backends,
            "hostname": self._hostname if self.options.get("include_hostname", True) else "",
            "time": time.time(),
        }
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(payload)
                self._stats["dropped"] += 1
            except Exception:
                self._stats["dropped"] += 1

    # ── worker ─────────────────────────────────────────────────────────────

    def _worker_loop(self):
        _log("Worker started.")
        while not self._stop.is_set():
            try:
                payload = self._queue.get(timeout=2)
            except queue.Empty:
                continue
            try:
                self._dispatch(payload)
            except Exception as e:
                _log(f"Dispatch error: {e}", "ERROR")
        _log("Worker stopped.")

    def _dispatch(self, payload):
        event = payload.get("event", "custom")
        requested = payload.get("backends")
        rate_limit = float(self.options.get("rate_limit", 10))
        dedup_window = float(self.options.get("dedup_window", 300))
        now = time.time()

        key = f"{payload['title']}|{payload['message']}"
        if key in self._dedup_cache:
            if now - self._dedup_cache[key] < dedup_window:
                self._stats["dropped"] += 1
                return
        self._dedup_cache[key] = now
        while len(self._dedup_cache) > 200:
            self._dedup_cache.popitem(last=False)

        hostname = payload.get("hostname", "")
        msg = f"[{hostname}] {payload['message']}" if hostname else payload["message"]

        for name, cfg, sender_fn in self._active_backends:
            if requested and name not in requested:
                continue
            allowed = cfg.get("events", [])
            if allowed and event not in allowed:
                continue
            last = self._last_send.get(name, 0)
            if now - last < rate_limit:
                time.sleep(rate_limit - (now - last))
            try:
                ok = sender_fn(cfg, title=payload["title"], message=msg,
                               priority=payload.get("priority", 0),
                               gps=payload.get("gps"), fields=payload.get("fields"),
                               event=event, hostname=hostname)
                self._last_send[name] = time.time()
                if ok:
                    self._stats["sent"] += 1
                    _log(f"Sent via {name}: {payload['title'][:40]}", "DEBUG")
                else:
                    self._stats["failed"] += 1
                    _log(f"Failed via {name}", "WARNING")
            except Exception as e:
                self._stats["failed"] += 1
                _log(f"{name} error: {e}", "ERROR")

    # ── backend discovery ──────────────────────────────────────────────────

    def _discover_backends(self):
        self._active_backends = []
        for name, fn in _BACKENDS.items():
            cfg = self.options.get(name, {})
            if isinstance(cfg, dict) and cfg.get("enabled", False):
                self._active_backends.append((name, cfg, fn))

    # ── GPS ────────────────────────────────────────────────────────────────

    def _get_gps(self, agent=None, pcap_filename=None):
        if agent is not None:
            try:
                info = agent.session()
                g = info.get("gps", {})
                lat, lng = g.get("Latitude", 0), g.get("Longitude", 0)
                if lat != 0 and lng != 0:
                    return {"lat": lat, "lng": lng, "alt": g.get("Altitude", 0)}
            except Exception:
                pass
        if pcap_filename:
            base = os.path.splitext(pcap_filename)[0]
            for ext, lk, nk in [(".gps.json", "Latitude", "Longitude"),
                                (".geo.json", "location", None),
                                (".paw-gps.json", "lat", "long")]:
                gf = base + ext
                if os.path.isfile(gf):
                    try:
                        with open(gf) as f:
                            d = json.load(f)
                        if ext == ".geo.json":
                            loc = d.get("location", {})
                            la, ln = loc.get("lat"), loc.get("lng")
                        else:
                            la, ln = d.get(lk), d.get(nk)
                        if la and ln:
                            return {"lat": float(la), "lng": float(ln)}
                    except Exception:
                        continue
        return None
