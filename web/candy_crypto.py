#!/usr/bin/env python3
"""Candy Simply-Fi local API helpers (offline only).

Re-implements, from static analysis of it.candy.simplyfi 3.14.1 (candy_simplify.apk):
  * the XOR + hex payload scheme   (it.candyhoover.core.classes.utilities.CandySecurityUtility)
  * pairing-key derivation          (CandySecurityUtility.calculateEncriptionKeyForConf /
                                     calculateEncriptionKey)
  * command strings for the two washer protocols:
      - "wifible" washers / washer-dryers  (washer.axibianca.model.command.Command & subclasses)
      - "dual" DualTech washers / washer-dryers (models.commands.CandyWasherDTCommand)
  * URL builders for http-read.json, http-write.json and http-config.json
  * a status decoder for the "statusLavatrice" object (CandyWasher.updateWithStatus)

This module never opens a network connection. It only builds strings; sending them is
up to the caller. Run it directly to execute the self-test.
"""

from __future__ import annotations

import json
import secrets
from typing import Iterable, Mapping, Sequence, Tuple, Union
from urllib.parse import quote

__all__ = [
    "xor_encrypt", "xor_decrypt", "xor_decrypt_app_compat",
    "config_key_from_ap_ssid", "startup_key_from_ap_ssid", "new_session_key",
    "params_to_string", "parse_param_string",
    "read_url", "write_url", "config_url",
    "wifible_start", "wifible_stop", "wifible_pause", "wifible_resume",
    "wifible_restart_good_night", "wifible_checkup", "wifible_autodose", "wifible_set_hardness",
    "wifible_get_statistics",
    "dual_start", "dual_stop",
    "decode_status",
]

Params = Union[str, Mapping[str, object], Sequence[Tuple[str, object]]]


# --------------------------------------------------------------------------- crypto

def xor_encrypt(plaintext: str, key: str) -> str:
    """CandySecurityUtility.xorEncrypt: UTF-8 bytes XOR key bytes (repeating), upper-case hex."""
    if not key:
        raise ValueError("empty key")
    m, k = plaintext.encode("utf-8"), key.encode("utf-8")
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(m)).hex().upper()


def xor_decrypt(hex_payload: str, key: str) -> str:
    """Inverse of xor_encrypt, done on bytes (correct for any content).

    Whitespace is stripped because the appliance's HTTP body may end with a newline
    (the app reads it with readLine()/string(); not verified on a device)."""
    if not key:
        raise ValueError("empty key")
    data = bytes.fromhex("".join(hex_payload.split()))
    k = key.encode("utf-8")
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(data)).decode("utf-8", "replace")


def xor_decrypt_app_compat(hex_payload: str, key: str) -> str:
    """Bit-for-bit copy of the app's CandySecurityUtility.xorDecrypt.

    The app first decodes the hex to a *string* (UTF-8) and XORs characters, which only
    equals xor_decrypt for 7-bit ASCII. Kept to document the behaviour."""
    s = bytes.fromhex("".join(hex_payload.split())).decode("utf-8", "replace")
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))


# --------------------------------------------------------------------------- keys

def _clean_ssid(ssid: str, replace_spaces: bool) -> str:
    """CandyStringUtility.cleanSSID: drop double quotes; non-Bianca/Axi types map ' ' -> '$'."""
    s = ssid.replace('"', "")
    return s.replace(" ", "$") if replace_spaces else s


def config_key_from_ap_ssid(ap_ssid: str, replace_spaces: bool = True) -> str:
    """Key for http-config.json during pairing (calculateEncriptionKeyForConf).

    = last 8 characters of the appliance access-point SSID the phone is connected to,
    written twice. replace_spaces is False for BIANCA / RED_DEVIL_AXI(_AD) / RED_DEVIL_TFT(_AD) /
    HWASH700 interface types, True otherwise."""
    s = _clean_ssid(ap_ssid, replace_spaces)
    tail = s[-8:] if len(s) >= 8 else ""   # app catches the exception and uses ""
    return tail + tail


def startup_key_from_ap_ssid(ap_ssid: str, replace_spaces: bool = True) -> str:
    """CandySecurityUtility.getStartupKey: FIRST 8 chars doubled (no caller found for washers)."""
    s = _clean_ssid(ap_ssid, replace_spaces)[:8]
    return s + s


def new_session_key(app_compatible: bool = True) -> str:
    """A 16-character session key for ENCRYPT_KEY during pairing.

    The app (calculateEncriptionKey) seeds java.util.Random with the current time and calls
    nextInt(14), so its keys only ever contain 'a'..'n' (every demo key in the bundled DB
    matches). app_compatible=True keeps that alphabet but uses a CSPRNG; whether the
    appliance accepts other characters is unknown."""
    alphabet = "abcdefghijklmn" if app_compatible else \
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))


# --------------------------------------------------------------------------- params

def params_to_string(params: Params) -> str:
    """Join parameters as key=value&... exactly like the app (no URL-encoding of values)."""
    if isinstance(params, str):
        return params
    items: Iterable[Tuple[str, object]] = params.items() if isinstance(params, Mapping) else params
    return "&".join(f"{k}={v}" for k, v in items)


def parse_param_string(s: str) -> dict:
    out = {}
    for part in s.split("&"):
        if part:
            k, _, v = part.partition("=")
            out[k] = v
    return out


# --------------------------------------------------------------------------- URLs

def read_url(ip: str, encrypted: bool = True) -> str:
    """Status: GET http://<ip>/http-read.json?encrypted=1 -> hex body, XOR with the key."""
    return f"http://{ip}/http-read.json?encrypted={1 if encrypted else 0}"


def write_url(ip: str, params: Params, key: str | None = None, encrypted: bool = True) -> str:
    """Command: GET http://<ip>/http-write.json?encrypted=1&data=<HEX>.

    encrypted=False reproduces the app's debug path (?encrypted=0&k=v&...); values are
    percent-encoded the way an HTTP client (Retrofit @QueryMap) would. Whether production
    firmware accepts encrypted=0 is unknown."""
    plain = params_to_string(params)
    if encrypted:
        if not key:
            raise ValueError("key required for encrypted=1")
        return f"http://{ip}/http-write.json?encrypted=1&data={xor_encrypt(plain, key)}"
    q = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in parse_param_string(plain).items())
    return f"http://{ip}/http-write.json?encrypted=0&{q}"


def config_url(ssid: str, password: str, ntw_mode: int, session_key: str, ap_ssid: str,
               ap_ip: str = "192.168.0.1", replace_spaces: bool = True) -> str:
    """Pairing request sent while the phone is on the appliance's own Wi-Fi AP.

    Plaintext NTW_MODE=..&SSID=..&PASSWORD=..&ENCRYPT_KEY=<session_key>, XOR'd with
    config_key_from_ap_ssid(ap_ssid). The reply is XOR'd with session_key and should
    contain {"response":"success"} (ConnectionManager.configureApplianceEncrypted)."""
    plain = params_to_string([
        ("NTW_MODE", ntw_mode),
        ("SSID", _clean_ssid(ssid, replace_spaces)),
        ("PASSWORD", password.replace(" ", "$") if replace_spaces else password),
        ("ENCRYPT_KEY", session_key),
    ])
    ck = config_key_from_ap_ssid(ap_ssid, replace_spaces)
    if not ck:
        raise ValueError("AP SSID shorter than 8 characters; app would refuse")
    return f"http://{ap_ip}/http-config.json?encrypted=1&data={xor_encrypt(plain, ck)}"


# --------------------------------------------------------------------------- wifible commands

def wifible_start(*, prnm: int, prcode: int, prstr: str = "Program", temp: int | None = None,
                  soil: int = 0, spin_rpm: int | None = None, optmsk1: int = 0, optmsk2: int = 0,
                  lang: int = 1, steam: int = 0, dry: int = 0, extra_dose: int = 0,
                  recipe_id: str = "0", delay_steps: int = 0, checkup: bool = False) -> str:
    """Start string built by axibianca Command.getParameterString (order preserved).

    Values are converted the way the app's Command.setProgram does:
      temp None/255 ("not adjustable") -> TmpTgt omitted; spin None/255 -> SpdTgt=0 (still sent).
    Soil must already be within the programme's range (the app falls back to its minimum).
    '&' and '=' are removed from the programme name so they can't split the parameter string.
    delay_steps: 30-minute steps (0..48), sent with StSt=1."""
    name = prstr.replace("&", "and").replace("=", "")
    p = [("StSt", 1), ("DelVl", delay_steps), ("PrNm", prnm), ("PrCode", prcode), ("PrStr", name)]
    if temp is not None and temp != 255:
        p.append(("TmpTgt", temp))
    p.append(("SLevTgt", 0 if soil == 255 else soil))
    p.append(("SpdTgt", 0 if spin_rpm is None or spin_rpm == 255 else spin_rpm // 100))
    p += [("OptMsk1", optmsk1), ("OptMsk2", optmsk2), ("Lang", lang), ("Stm", steam), ("Dry", dry),
          ("ED", extra_dose), ("RecipeId", recipe_id), ("StartCheckUp", 1 if checkup else 0),
          ("DispTestOn", 1)]
    return "Write=1&" + params_to_string(p)


def wifible_stop(current_prnm: int | None, delayed: bool = False) -> str:
    """StopCommand: Write=1&StSt=0[&PrNm=<status PrNm>][&DelVl=0]."""
    s = "Write=1&StSt=0"
    if current_prnm is not None:
        s += f"&PrNm={current_prnm}"
    if delayed:
        s += "&DelVl=0"
    return s


def wifible_pause() -> str:
    """AxiPauseWasherCommand(pause=true). The 'encrypted=0&' prefix is part of the payload."""
    return "encrypted=0&Pa=1"


def wifible_resume() -> str:
    return "encrypted=0&Pa=0"


def wifible_restart_good_night() -> str:
    return "Write=1&RestartGN=1"


def wifible_checkup(hwash700: bool = False) -> str:
    return "StartCheckUp=1" if hwash700 else "CheckUpState=1"


def wifible_autodose(detergent: bool, softener: bool) -> str:
    return f"Write=1&SetDet={int(detergent)}&SetSoft={int(softener)}"


def wifible_set_hardness(level: int) -> str:
    return f"SetHard={level}"


def wifible_get_statistics() -> str:
    return "GetStat=1"


# --------------------------------------------------------------------------- dual commands

def dual_start(*, prnm: int, default_temp: int, default_spin_rpm: int, default_soil: int,
               temp: int | None = None, spin_rpm: int | None = None, soil: int | None = None,
               optmsk: int = 0, steam: int = 0, dry: int | None = None, recipe_id: str = "0",
               delay_steps: int = 0, dry_only: bool = False, prcode: int | None = None) -> str:
    """CandyWasherCommand + CandyWasherDTCommand.getParameterString.

    Values equal to the programme default (or 255) are omitted, as the app does.
    dry: pass for washer-dryers (sent as Option=, 1 extra / 2 cupboard / 3 iron ... see
    commands.json); None for plain washers. dry_only: programme family 'D'.
    prcode: some firmware (SMARTPRO_5DIG_STM_NEL) requires PrCode even in dual protocol."""
    s = f"Write=1&Pa=0&Sel=0&PrNm={prnm}"
    if prcode is not None:
        s += f"&PrCode={prcode}"
    s += f"&DelMd=1&DelVl={delay_steps}" if delay_steps > 0 else "&StSt=1"
    if not dry_only:
        t = default_temp if temp is None else temp
        if t != default_temp and t != 255:
            s += f"&TmpTgt={t}&TmpDf={default_temp}"
        sl = default_soil if soil is None else soil
        if sl != default_soil and sl != 255:
            if t == 90 and sl == 1:
                sl = 2
            s += f"&SLevTgt={sl}"
        sp = default_spin_rpm if spin_rpm is None else spin_rpm
        if sp != default_spin_rpm and sp != 255:
            s += f"&SpdTgt={sp // 100}&SpdDef={default_spin_rpm // 100}"
    # DT subclass omits OptMsk when 0 (appendOptionMask override)
    if optmsk > 0:
        s += f"&OptMsk={optmsk}"
    d = dry if dry is not None else 0
    s += f"&Stm={steam}&Dry={d}&Option={d}"
    return s + f"&RecipeId={recipe_id}&CheckUpState=0"


def dual_stop(current_pr: int) -> str:
    return f"Write=1&StSt=0&DelMd=0&PrNm={current_pr}"


# --------------------------------------------------------------------------- status

MACHINE_MODE = {0: "no state", 1: "selection", 2: "running", 3: "paused", 4: "delayed start (selection)",
                5: "delayed start (counting down)", 6: "error", 7: "finished"}
PHASE = {0: "none", 1: "prewash", 2: "wash", 3: "rinse", 4: "last rinse", 5: "end", 6: "drying",
         7: "error", 8: "steam", 9: "good-night pause", 255: "n/a"}
OPTION_BITS = {1: "prewash", 2: "hygiene", 4: "anti-crease", 8: "good night", 16: "rinse+1",
               32: "rinse+2", 64: "rinse+3", 128: "aquaplus"}


def decode_status(body: Union[str, dict], key: str | None = None) -> dict:
    """Decode an http-read.json reply (hex if key is given, else JSON) into readable fields."""
    if isinstance(body, str):
        body = json.loads(xor_decrypt(body, key) if key else body)
    st = body.get("statusLavatrice", body)

    def i(name):
        try:
            return int(st[name])
        except (KeyError, TypeError, ValueError):
            return None
    out = {"raw": st}
    mm = i("MachMd")
    out["machine_mode"] = (mm, MACHINE_MODE.get(mm))
    ph = i("PrPh")
    out["phase"] = (ph, PHASE.get(ph))
    out["program_number"] = i("PrNm") if i("PrNm") is not None else i("Pr")
    out["program_code"] = i("PrCode")
    out["temperature_C"] = i("Temp")
    sp = i("SpinSp")
    out["spin_rpm"] = None if sp is None else (sp * 100 if sp < 100 else sp)
    out["soil_level"] = i("SLevel")
    out["remaining_time_s"] = i("RemTime")          # seconds (inferred)
    out["delay_value"] = i("DelVal")                # unit unclear, see docs/protocol.md
    out["remote_control_enabled"] = (st.get("WiFiStatus") in ("1", 1, "true")) if "WiFiStatus" in st else None
    out["error_code"] = st.get("Err")
    mask = 0
    for n in range(1, 9):
        if i(f"Opt{n}"):
            mask |= 1 << (n - 1)
    out["options_mask1"] = mask
    out["options"] = [v for b, v in OPTION_BITS.items() if mask & b]
    out["steam"] = i("Steam")
    out["dry_type"] = i("DryT")
    out["recipe_id"] = st.get("RecipeId")
    return out


# --------------------------------------------------------------------------- self-test

def _selftest() -> None:
    # Demo appliance keys shipped in assets/candy_database.sql, table configured_appliances.
    demo_keys = {
        "ROW 4854DXH\\1-S (washer_dryer, RAPIDO_4DIG_STM, wifible)": "ainackjmbnnnbjcd",
        "GVF4137TWHN/2-07 (washer, 3D_DUAL, dual)": "lahncebdcbhnaebb",
        "RO 1284DWH7\\1-S (washer, RAPIDO_4DIG_STM, wifible)": "dmdjkfcijhlehbdf",
        "GSF 1510LWH3/1-01 (washer, 4D, wifi)": "kegiknjhjmbifeib",
        "CDPM 95390XF (dishwasher)": "lnfamncjcffnceaa",
        "CFID 36 WIFI (hob)": "hbbfcekfjcjdddmm",
    }
    for name, k in demo_keys.items():
        assert len(k) == 16 and set(k) <= set("abcdefghijklmn"), name
    wd_key = demo_keys["ROW 4854DXH\\1-S (washer_dryer, RAPIDO_4DIG_STM, wifible)"]
    dual_key = demo_keys["GVF4137TWHN/2-07 (washer, 3D_DUAL, dual)"]

    # Known-answer vectors (computed independently with a byte XOR one-liner).
    assert xor_encrypt("Write=1&StSt=0&PrNm=11", wd_key) == "361B071506565B4B311A3D1A5F5A45341327035C525A"
    assert xor_encrypt("Write=1&StSt=0&DelMd=0&PrNm=6", dual_key) == \
        "3B13011A0658534230163B1A5C554426090D250A5E554434112C055357"
    assert xor_decrypt("361B071506565B4B311A3D1A5F5A45341327035C525A", wd_key) == "Write=1&StSt=0&PrNm=11"

    # wifible start for the demo washer-dryer's "Eco Cottons" (PrNm 11, pr_code 2, default 40C,
    # 1400 rpm, soil 3, steam=5 toggle, dry=255 selectable) with cupboard drying.
    cmd = wifible_start(prnm=11, prcode=2, prstr="Eco Cottons", temp=40, soil=3, spin_rpm=1400,
                        optmsk1=0, lang=1, steam=0, dry=3)
    assert cmd == ("Write=1&StSt=1&DelVl=0&PrNm=11&PrCode=2&PrStr=Eco Cottons&TmpTgt=40&SLevTgt=3"
                   "&SpdTgt=14&OptMsk1=0&OptMsk2=0&Lang=1&Stm=0&Dry=3&ED=0&RecipeId=0"
                   "&StartCheckUp=0&DispTestOn=1"), cmd
    url = write_url("192.0.2.10", cmd, wd_key)
    assert url.startswith("http://192.0.2.10/http-write.json?encrypted=1&data=")
    assert xor_decrypt(url.split("data=", 1)[1], wd_key) == cmd
    assert xor_decrypt_app_compat(xor_encrypt(cmd, wd_key), wd_key) == cmd
    # Not-adjustable values and a name with '&', converted like Command.setProgram.
    cmd = wifible_start(prnm=9, prcode=77, prstr="Rapid Wash & Dry 59'", temp=255, soil=0, spin_rpm=255, dry=8)
    assert cmd == ("Write=1&StSt=1&DelVl=0&PrNm=9&PrCode=77&PrStr=Rapid Wash and Dry 59'&SLevTgt=0"
                   "&SpdTgt=0&OptMsk1=0&OptMsk2=0&Lang=1&Stm=0&Dry=8&ED=0&RecipeId=0&StartCheckUp=0"
                   "&DispTestOn=1"), cmd

    # Pause / resume / stop strings.
    assert wifible_pause() == "encrypted=0&Pa=1" and wifible_resume() == "encrypted=0&Pa=0"
    assert wifible_stop(11) == "Write=1&StSt=0&PrNm=11"
    assert wifible_stop(11, delayed=True) == "Write=1&StSt=0&PrNm=11&DelVl=0"

    # dual start for the demo 3D_DUAL washer-dryer "Cottons" (PrNm 6, 40C/1400/soil 3):
    # 60C, 1000 rpm, prewash, iron dry (Option=3 on dual).
    d = dual_start(prnm=6, default_temp=40, default_spin_rpm=1400, default_soil=3,
                   temp=60, spin_rpm=1000, optmsk=1, dry=3)
    assert d == ("Write=1&Pa=0&Sel=0&PrNm=6&StSt=1&TmpTgt=60&TmpDf=40&SpdTgt=10&SpdDef=14"
                 "&OptMsk=1&Stm=0&Dry=3&Option=3&RecipeId=0&CheckUpState=0"), d
    assert dual_start(prnm=6, default_temp=40, default_spin_rpm=1400, default_soil=3,
                      delay_steps=4).startswith("Write=1&Pa=0&Sel=0&PrNm=6&DelMd=1&DelVl=4&Stm=0")  # OptMsk omitted when 0
    assert dual_stop(6) == "Write=1&StSt=0&DelMd=0&PrNm=6"

    # Unencrypted debug URL form.
    assert write_url("192.0.2.10", "Write=1&StSt=0&PrNm=11", encrypted=False) == \
        "http://192.0.2.10/http-write.json?encrypted=0&Write=1&StSt=0&PrNm=11"
    assert read_url("192.0.2.10") == "http://192.0.2.10/http-read.json?encrypted=1"

    # Pairing: the app's placeholder AP name for washers is "WIFIWASHMACHINE-xyzk"
    # (CandyWasher.pseudoNetwork); real SSIDs differ per appliance.
    assert config_key_from_ap_ssid("WIFIWASHMACHINE-xyzk") == "INE-xyzkINE-xyzk"
    sk = new_session_key()
    assert len(sk) == 16 and set(sk) <= set("abcdefghijklmn")
    cu = config_url("My Home", "pass word", 3, "ainackjmbnnnbjcd", "WIFIWASHMACHINE-xyzk")
    plain = xor_decrypt(cu.split("data=", 1)[1], config_key_from_ap_ssid("WIFIWASHMACHINE-xyzk"))
    assert plain == "NTW_MODE=3&SSID=My$Home&PASSWORD=pass$word&ENCRYPT_KEY=ainackjmbnnnbjcd", plain

    # Status decoding (synthetic reply; no sample status is bundled in the APK).
    sample = {"statusLavatrice": {"WiFiStatus": "1", "Err": "255", "MachMd": "2", "Pr": "11", "PrPh": "2",
                                  "SLevel": "3", "Temp": "40", "SpinSp": "14", "Opt1": "1", "Opt2": "0",
                                  "Opt8": "1", "RemTime": "8400", "DelVal": "0", "PrCode": "2",
                                  "Steam": "0", "DryT": "3"}}
    enc = xor_encrypt(json.dumps(sample), wd_key)
    st = decode_status(enc, wd_key)
    assert st["machine_mode"] == (2, "running") and st["phase"] == (2, "wash")
    assert st["spin_rpm"] == 1400 and st["options"] == ["prewash", "aquaplus"] and st["program_number"] == 11

    print("candy_crypto self-test: all checks passed (no network used)")


if __name__ == "__main__":
    _selftest()
