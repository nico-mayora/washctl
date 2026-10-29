#!/usr/bin/env python3
"""Retrieve your washer-dryer's encryption key from the Candy cloud.

Usage:
    python3 get_key.py
    python3 get_key.py --email you@example.com --password yourpass
    python3 get_key.py --email you@example.com --password yourpass --save

With --save, writes the first appliance's config to config.json so the web
UI only needs the IP filled in.

Authentication goes through the real Salesforce CIAM login page (headless
Chromium via Playwright), exactly as the mobile app does it.
"""

import argparse
import asyncio
import base64
import getpass
import hashlib
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse

try:
    import httpx
except ImportError:
    sys.exit("httpx not installed.  Run: pip install httpx")

try:
    from playwright.async_api import async_playwright
except ImportError:
    sys.exit(
        "playwright not installed.  Run: pip install playwright && playwright install chromium"
    )

# Salesforce Connected App credentials (from Candy Simply-Fi APK)
SF_LOGIN_URL = "https://account.candy-home.com/CandyApp"
SF_CONSUMER_KEY = (
    "3MVG9QDx8IX8nP5T2Ha8ofvlmjKuido4mcuSVCv4GwStG0Lf84ccYQylvDYy9d_ZLtnyAPzJt4khJoNYn_QVB"
)
REDIRECT_URI = "candy://mobilesdk/detect/oauth/done"

# Simply-Fi API
SIMPLY_FI_BASE = "https://simply-fi.herokuapp.com"

ENV_PATH = Path(__file__).parent / ".env"
SCRATCHPAD = Path("/tmp/candy_debug")


def load_env():
    if not ENV_PATH.exists():
        return {}
    env = {}
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def _make_pkce():
    """Generate PKCE code_verifier + code_challenge (S256)."""
    verifier = secrets.token_urlsafe(43)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


async def sf_login_browser(email: str, password: str, *, debug: bool = False) -> dict:
    """Drive Salesforce OAuth authorization-code + PKCE flow via headless Chromium.

    Returns dict with 'access_token' and usually 'refresh_token'.
    """
    code_verifier, code_challenge = _make_pkce()

    auth_url = (
        f"{SF_LOGIN_URL}/services/oauth2/authorize?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": SF_CONSUMER_KEY,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "display": "touch",
            }
        )
    )

    captured_code: str | None = None

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()

        # --- capture the candy:// redirect containing ?code=... ---
        def try_capture(url: str, source: str):
            nonlocal captured_code
            if captured_code:
                return
            if "candy://mobilesdk" not in url:
                return
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            code = qs.get("code", [None])[0]
            if code:
                captured_code = code
                if debug:
                    print(f"  [debug] Captured code via {source}")
            elif debug:
                # Also try fragment in case server sends hybrid
                print(f"  [debug] candy:// redirect seen via {source} but no code in query")
                print(f"  [debug]   url: {url[:200]}")

        def on_response(resp):
            loc = resp.headers.get("location", "")
            if loc:
                try_capture(loc, f"Location header ({resp.status})")
            if debug and resp.status in (301, 302, 303, 307, 308):
                print(f"  [debug] {resp.status}: -> {loc[:200]}")

        def on_request(req):
            try_capture(req.url, "request")

        page.on("response", on_response)
        page.on("request", on_request)
        page.on("requestfailed", on_request)

        # --- navigate to login page ---
        if debug:
            print(f"  [debug] Auth URL: {auth_url[:100]}...")
        try:
            await page.goto(auth_url, wait_until="networkidle", timeout=30_000)
        except Exception as e:
            if debug:
                print(f"  [debug] goto exception (may be expected): {e}")

        if captured_code:
            await browser.close()
            return await _exchange_code(captured_code, code_verifier)

        # --- fill login form ---
        if debug:
            print(f"  [debug] Page URL: {page.url[:120]}")
            SCRATCHPAD.mkdir(parents=True, exist_ok=True)
            try:
                await page.screenshot(
                    path=str(SCRATCHPAD / "01_login.png"), full_page=True, timeout=10_000
                )
            except Exception:
                pass

        try:
            await page.fill("input[name='username']", email, timeout=5_000)
            await page.fill("input[name='pw']", password, timeout=5_000)
            await page.click("input#Login", timeout=5_000)
        except Exception:
            await browser.close()
            sys.exit("Could not find login form on the Salesforce page.")

        if debug:
            print("  [debug] Submitted login form, waiting for auth page...")

        # Wait for navigation after login
        try:
            await page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass

        if captured_code:
            await browser.close()
            return await _exchange_code(captured_code, code_verifier)

        # --- handle OAuth consent page (RemoteAccessAuthorizationPage) ---
        if debug:
            print(f"  [debug] Post-login URL: {page.url[:120]}")
            try:
                await page.screenshot(
                    path=str(SCRATCHPAD / "02_post_login.png"),
                    full_page=True,
                    timeout=10_000,
                )
            except Exception:
                pass

        # The consent page has an "Allow" button
        for allow_sel in [
            "input#oaapprove",           # standard Salesforce Allow
            "button#oaapprove",
            "input[name='approve']",
            "button[name='approve']",
            "#oaapprove",
            "input[value='Allow']",
            "button:has-text('Allow')",
        ]:
            try:
                await page.click(allow_sel, timeout=3_000)
                if debug:
                    print(f"  [debug] Clicked consent button: {allow_sel}")
                break
            except Exception:
                continue

        # Wait for redirect after consent
        for tick in range(30):
            if captured_code:
                break
            await asyncio.sleep(0.5)

        if not captured_code:
            # Last resort: check page URL
            try:
                u = page.url
                if "candy://mobilesdk" in u:
                    qs = parse_qs(urlparse(u).query)
                    captured_code = qs.get("code", [None])[0]
            except Exception:
                pass

        if debug and not captured_code:
            SCRATCHPAD.mkdir(parents=True, exist_ok=True)
            try:
                await page.screenshot(
                    path=str(SCRATCHPAD / "03_timeout.png"),
                    full_page=True,
                    timeout=10_000,
                )
                (SCRATCHPAD / "03_page.html").write_text(await page.content())
                print(f"  [debug] Timeout. URL: {page.url[:120]}")
                print(f"  [debug] Screenshots in {SCRATCHPAD}/")
            except Exception:
                pass

        await browser.close()

    if not captured_code:
        sys.exit(
            "Login did not produce an OAuth authorization code within 30 s.\n"
            "Check your email / password. Run with --debug for screenshots."
        )

    return await _exchange_code(captured_code, code_verifier)


async def _exchange_code(code: str, code_verifier: str) -> dict:
    """Exchange authorization code for tokens via PKCE."""
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{SF_LOGIN_URL}/services/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": SF_CONSUMER_KEY,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": code_verifier,
            },
        )
        if r.status_code in (400, 401, 403):
            try:
                body = r.json()
                err = body.get("error_description") or body.get("error") or r.text
            except Exception:
                err = r.text
            sys.exit(f"Token exchange failed ({r.status_code}): {err}")
        r.raise_for_status()
        return r.json()


def get_openid_token(refresh_token: str) -> str | None:
    """Exchange refresh token for an OpenID Connect JWT."""
    try:
        r = httpx.post(
            f"{SF_LOGIN_URL}/services/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "client_id": SF_CONSUMER_KEY,
                "refresh_token": refresh_token,
                "format": "openidconnect",
            },
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        return data.get("id_token") or data.get("access_token")
    except Exception:
        return None


def get_appliances(token: str) -> list | None:
    """Fetch appliance list from Simply-Fi API.  Returns None on auth failure."""
    r = httpx.get(
        f"{SIMPLY_FI_BASE}/api/v1/appliances.json",
        params={"with_programs": "1"},
        headers={
            "Authorization": f"Bearer {token}",
            "Salesforce-Auth": "1",
            "Brand": "0",
            "Device-Family": "android",
        },
        timeout=30,
    )
    if r.status_code in (401, 403):
        return None
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        data = data.get("appliances", data.get("data", [data]))

    # Unwrap {"appliance": {...}} wrappers
    unwrapped = []
    for item in data:
        if isinstance(item, dict) and "appliance" in item and len(item) == 1:
            unwrapped.append(item["appliance"])
        else:
            unwrapped.append(item)
    return unwrapped


PROGRAMME_NAME_MAP = {
    "DUAL_WM_WD_OFF": "Off",
    "DUAL_WM_WD_PROGRAM_NAME_COTTONS": "Cottons",
    "DUAL_WM_WD_PROGRAM_NAME_ECO_40_60_NEW_ENERGY_LABEL": "Eco 40-60",
    "DUAL_WM_WD_PROGRAM_NAME_COTTONS_PREWASH": "Cottons + Prewash",
    "DUAL_WM_WD_PROGRAM_NAME_SYNTHETIC_AND_COLOURED": "Synthetics & Coloured",
    "DUAL_WM_WD_PROGRAM_NAME_RINSE": "Rinse",
    "DUAL_WM_WD_PROGRAM_NAME_DRAIN_SPIN": "Drain + Spin",
    "DUAL_WM_WD_PROGRAM_NAME_WOOL_DRY": "Wool Dry",
    "DUAL_WM_WD_PROGRAM_NAME_LOW_DRY": "Low Dry",
    "DUAL_WM_WD_PROGRAM_NAME_HIGH_DRY": "High Dry",
    "DUAL_WM_WD_PROGRAM_NAME_WOOL_AND_DELICATES_49": "Wool & Delicates 49'",
    "DUAL_WM_WD_PROGRAM_NAME_RAPID_14": "Rapid 14'",
    "DUAL_WM_WD_PROGRAM_NAME_RAPID_30": "Rapid 30'",
    "DUAL_WM_WD_PROGRAM_NAME_RAPID_44": "Rapid 44'",
    "DUAL_WM_WD_PROGRAM_NAME_MIX_AND_COLOUR_59": "Mix & Colour 59'",
    "DUAL_WM_WD_PROGRAM_NAME_PERFECT_COTTON_59": "Perfect Cotton 59'",
    "DUAL_WM_WD_PROGRAM_NAME_SPECIAL_49": "Special 49'",
    "DUAL_WM_WD_PROGRAM_NAME_TUMBLING": "Tumbling",
    "DUAL_WM_WD_PROGRAM_NAME_HYGIENE_60": "Hygiene 60°",
    "DUAL_WM_WD_PROGRAM_NAME_DELICATES": "Delicates",
    "DUAL_WM_WD_PROGRAM_NAME_AUTOCLEAN": "Auto-Clean",
    "DUAL_WM_WD_PROGRAM_NAME_INTENSIVE_40": "Intensive 40°",
    "DUAL_WM_WD_PROGRAM_NAME_RAPID_WASH_AND_DRY_59_MIN": "Rapid Wash & Dry 59'",
}


def _cloud_name_to_english(name_key: str) -> str:
    return PROGRAMME_NAME_MAP.get(name_key, name_key.replace("DUAL_WM_WD_PROGRAM_NAME_", "").replace("_", " ").title())


def _int_or_none(val: str) -> int | None:
    if val is None or val == "" or val == "NULL":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def convert_cloud_programmes(raw_programs: list) -> list:
    """Convert cloud API programme format to the UI format."""
    result = []
    for p in raw_programs:
        if isinstance(p, dict) and "program" in p:
            p = p["program"]
        name_key = p.get("name", "")
        if name_key == "DUAL_WM_WD_OFF":
            continue

        # Build param dict from command_parameters
        params = {}
        for cp in p.get("command_parameters", []):
            if isinstance(cp, dict) and "command_parameter" in cp:
                cp = cp["command_parameter"]
            if "name" in cp:
                params[cp["name"]] = cp.get("validation", cp.get("value", ""))

        prnm = _int_or_none(params.get("selector_position"))
        prcode = _int_or_none(params.get("pr_code"))
        default_temp = _int_or_none(params.get("default_temperature"))
        max_temp = _int_or_none(params.get("maximum_temperature"))
        default_spin = _int_or_none(params.get("default_spin_speed"))
        max_spin = _int_or_none(params.get("maximum_spin_speed"))
        default_soil = _int_or_none(params.get("default_soil_level"))
        min_soil = _int_or_none(params.get("minimum_soil_level"))
        max_soil = _int_or_none(params.get("maximum_soil_level"))
        opts = _int_or_none(params.get("available_options"))
        opts2 = _int_or_none(params.get("available_options2"))
        steam = _int_or_none(params.get("steam"))
        dry = _int_or_none(params.get("dry"))
        duration = _int_or_none(params.get("default_duration"))
        prog_type = params.get("program_type", "")

        if prog_type == "D" or (name_key and "DRY" in name_key.upper() and "WASH" not in name_key.upper()):
            family = "dry"
        elif any(kw in name_key.upper() for kw in ("RINSE", "DRAIN", "SPIN", "CLEAN", "TUMBL")):
            family = "utility"
        else:
            family = "wash"

        entry = {
            "name_key": name_key,
            "name_en": _cloud_name_to_english(name_key),
            "selector_position_PrNm": prnm,
            "program_code_PrCode": prcode,
            "family": family,
            "temperature_C": {
                "default": default_temp,
                "max": max_temp,
            },
            "spin_rpm": {
                "default": default_spin,
                "max": max_spin,
            },
            "soil_level": {
                "default": default_soil,
                "min": min_soil,
                "max": max_soil,
            },
            "available_options_raw": opts,
            "available_options2_raw": opts2,
            "steam_raw": steam,
            "dry_raw": dry,
            "default_duration_min": duration,
        }
        result.append(entry)
    return result


def print_appliances(appliances: list) -> tuple[dict | None, list]:
    """Print appliance info. Returns (washer_config, raw_programmes) for saving."""
    print(f"\nFound {len(appliances)} appliance(s):\n")
    print("-" * 72)

    washer_config = None
    raw_progs_for_save = []

    for i, a in enumerate(appliances, 1):
        info = a.get("additional_info") or {}
        name = (
            a.get("appliance_model_name")
            or a.get("name")
            or a.get("nick_name")
            or info.get("appliance_type_name")
            or "Unknown"
        )
        serial = a.get("sixteen_digits_code") or a.get("serial_number") or "?"
        key = a.get("encryption_key") or ""
        conn = a.get("connectivity") or info.get("connectivity") or "?"
        iface = a.get("interface_type") or info.get("interface_type") or "?"
        mac = a.get("mac_address") or "?"
        app_type = (
            a.get("appliance_type")
            or info.get("appliance_type_name")
            or a.get("type")
            or "?"
        )

        iface_lower = str(iface).lower()
        proto = (
            "dual"
            if "dual" in app_type.lower() or "smartpro" in iface_lower
            else ("wifible" if "wifible" in iface_lower else "unknown")
        )

        print(f"  [{i}] {name}")
        print(f"      Serial:       {serial}")
        print(f"      Type:         {app_type}")
        print(f"      Connectivity: {conn}")
        print(f"      Interface:    {iface}")
        print(f"      MAC:          {mac}")
        print(f"      Protocol:     {proto}")
        if key:
            print(f"      Key:          {key}")
        else:
            print(f"      Key:          (not set — appliance may not be paired)")
        print()

        if washer_config is None and key and app_type in ("washer", "washer_dryer"):
            washer_config = {"ip": "", "key": key, "protocol": proto, "mac": mac}
            raw_progs_for_save = a.get("programs") or []

        raw_programs = a.get("programs") or []
        programs = []
        for p in raw_programs:
            if isinstance(p, dict) and "program" in p and len(p) == 1:
                programs.append(p["program"])
            else:
                programs.append(p)
        if programs:
            print(f"      Programmes ({len(programs)}):")
            for p in programs:
                pname = p.get("name") or p.get("localized_name") or "?"
                raw_cps = p.get("command_parameters") or []
                cps = []
                for cp in raw_cps:
                    if isinstance(cp, dict) and "command_parameter" in cp:
                        cps.append(cp["command_parameter"])
                    else:
                        cps.append(cp)
                params = {
                    c["name"]: c.get("validation", c.get("value", ""))
                    for c in cps
                    if "name" in c
                }
                sel = params.get("selector_position", "?")
                pr_code = params.get("pr_code", "?")
                temp = params.get("default_temperature", "?")
                print(f"        PrNm={sel} PrCode={pr_code} {pname} ({temp}°)")
            print()

    print("-" * 72)
    return washer_config, raw_progs_for_save


async def async_main():
    parser = argparse.ArgumentParser(description="Get your Candy washer encryption key")
    parser.add_argument("--email", "-e", help="Candy account email")
    parser.add_argument("--password", "-p", help="Candy account password")
    parser.add_argument(
        "--save",
        "-s",
        action="store_true",
        help="Save config.json for the washer control app",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Save screenshots for troubleshooting"
    )
    args = parser.parse_args()

    env = load_env()
    email = args.email or env.get("CANDY_EMAIL") or input("Candy email: ").strip()
    password = (
        args.password or env.get("CANDY_PASSWORD") or getpass.getpass("Candy password: ")
    )

    if not email or not password:
        sys.exit("Email and password are required.")

    print(f"Opening Salesforce login for {email}...")
    tokens = await sf_login_browser(email, password, debug=args.debug)

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    if not access_token:
        sys.exit("Token exchange succeeded but no access_token in response.")

    # The Candy app sends a Salesforce OpenID JWT to Simply-Fi.
    token = None
    if refresh_token:
        print("Exchanging for OpenID token...")
        token = get_openid_token(refresh_token)
        if token:
            print("Got JWT.")

    if not token:
        token = access_token

    print("Fetching appliances...")
    appliances = get_appliances(token)

    if appliances is None and token != access_token:
        print("JWT rejected by Simply-Fi, retrying with access_token...")
        token = access_token
        appliances = get_appliances(token)

    if appliances is None:
        sys.exit("Simply-Fi API rejected the token (401/403).")

    if not appliances:
        sys.exit("No appliances found on this account.")

    if args.debug:
        SCRATCHPAD.mkdir(parents=True, exist_ok=True)
        (SCRATCHPAD / "appliances.json").write_text(
            json.dumps(appliances, indent=2, default=str)
        )
        print(f"  [debug] Raw appliances response saved to {SCRATCHPAD}/appliances.json")

    washer_config, raw_cloud_progs = print_appliances(appliances)

    if not args.save:
        return

    if not washer_config:
        print("No washer/washer-dryer with a key found; config not saved.")
        return

    cfg_path = Path(__file__).parent / "config.json"
    print(f"\nKey: {washer_config['key']}")
    print(f"Protocol: {washer_config['protocol']}")
    print(f"MAC: {washer_config['mac']}")

    # Auto-discover IP via UDP broadcast, then LAN scan fallback
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "discover", Path(__file__).parent / "discover.py"
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)

    print("\nListening for washer on UDP 55555 (15 s)...")
    result = await asyncio.get_event_loop().run_in_executor(
        None, _mod.discover_sync, washer_config["mac"], 15.0
    )
    if result:
        washer_config["ip"] = result["ip"]
        print(f"Found washer at {result['ip']}")
    else:
        print("No UDP broadcast received. Scanning LAN...")
        ip = await _mod.lan_scan(
            washer_config["key"], progress=lambda m: print(f"  {m}")
        )
        if ip:
            washer_config["ip"] = ip
            print(f"Found washer at {ip}")
        else:
            print("Washer not found on the network.")
            print("You can set the IP later in the web UI or config.json.")

    cfg_path.write_text(json.dumps(washer_config, indent=2))
    print(f"\nSaved config to {cfg_path}")

    # Convert and save real programmes from the cloud
    if raw_cloud_progs:
        converted = convert_cloud_programmes(raw_cloud_progs)
        progs_path = Path(__file__).parent / "my_programmes.json"
        progs_path.write_text(json.dumps(converted, indent=2))
        print(f"Saved {len(converted)} programmes to {progs_path}")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
