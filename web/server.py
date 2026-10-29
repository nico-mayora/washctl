#!/usr/bin/env python3
"""Candy washer-dryer local control server.

Proxies encrypted HTTP commands to the appliance and serves the web UI.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import candy_crypto as cc
from discover import discover_async, lan_scan

app = FastAPI(title="Washer Control")

PROGRAMMES_PATH = Path(__file__).parent / "programmes.json"
MY_PROGRAMMES_PATH = Path(__file__).parent / "my_programmes.json"
CONFIG_PATH = Path(__file__).parent / "config.json"
FAVOURITES_PATH = Path(__file__).parent / "favourites.json"

_config: dict = {}
_programmes: dict = {}
_last_status: dict = {}
_last_status_time: float = 0


def load_config() -> dict:
    global _config
    if CONFIG_PATH.exists():
        _config = json.loads(CONFIG_PATH.read_text())
    else:
        _config = {"ip": "", "key": "", "protocol": "wifible"}
    return _config


def save_config(cfg: dict):
    global _config
    _config = cfg
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def load_programmes() -> dict:
    global _programmes
    if not _programmes:
        _programmes = json.loads(PROGRAMMES_PATH.read_text())
    return _programmes


load_config()


async def washer_get(url: str, timeout: float = 8.0) -> str:
    async with httpx.AsyncClient() as client:
        r = await client.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text.strip()


async def _rediscover() -> str | None:
    """Try to find the washer at a new IP. Returns the IP or None."""
    cfg = load_config()
    mac, key = cfg.get("mac"), cfg.get("key")
    if mac:
        result = await discover_async(mac=mac, timeout=8.0)
        if result:
            cfg["ip"] = result["ip"]
            save_config(cfg)
            return result["ip"]
    if key:
        ip = await lan_scan(key)
        if ip:
            cfg["ip"] = ip
            save_config(cfg)
            return ip
    return None


# ---- Config endpoints ----

class ConfigBody(BaseModel):
    ip: str
    key: str
    protocol: str = "wifible"


@app.get("/api/config")
def get_config():
    cfg = load_config()
    return {"ip": cfg.get("ip", ""), "key": cfg.get("key", ""), "protocol": cfg.get("protocol", "wifible")}


@app.post("/api/config")
def set_config(body: ConfigBody):
    save_config(body.model_dump())
    return {"ok": True}


# ---- Status ----

@app.get("/api/status")
async def get_status(force: bool = False):
    global _last_status, _last_status_time
    cfg = load_config()
    if not cfg.get("ip") or not cfg.get("key"):
        raise HTTPException(400, "Washer IP and key not configured")

    if not force and _last_status and (time.time() - _last_status_time) < 3:
        return _last_status

    url = cc.read_url(cfg["ip"])
    try:
        raw = await washer_get(url)
    except Exception:
        new_ip = await _rediscover()
        if not new_ip:
            raise HTTPException(502, f"Cannot reach washer at {cfg['ip']} and re-discovery failed")
        cfg = load_config()
        raw = await washer_get(cc.read_url(new_ip))

    try:
        decoded = cc.decode_status(raw, cfg["key"])
    except Exception as e:
        raise HTTPException(502, f"Failed to decrypt/decode status: {e}")

    _last_status = decoded
    _last_status_time = time.time()
    return decoded


# ---- Commands ----

class StartBody(BaseModel):
    prnm: int
    prcode: int
    prstr: str = "Program"
    temp: Optional[int] = None
    soil: int = 0
    spin_rpm: Optional[int] = None
    optmsk1: int = 0
    optmsk2: int = 0
    lang: int = 1
    steam: int = 0
    dry: int = 0
    extra_dose: int = 0
    recipe_id: str = "0"
    delay_steps: int = 0


class DualStartBody(BaseModel):
    prnm: int
    default_temp: int
    default_spin_rpm: int
    default_soil: int
    temp: Optional[int] = None
    spin_rpm: Optional[int] = None
    soil: Optional[int] = None
    optmsk: int = 0
    steam: int = 0
    dry: Optional[int] = None
    recipe_id: str = "0"
    delay_steps: int = 0
    dry_only: bool = False
    prcode: Optional[int] = None


async def send_command(cmd: str) -> dict:
    cfg = load_config()
    if not cfg.get("ip") or not cfg.get("key"):
        raise HTTPException(400, "Not configured")
    url = cc.write_url(cfg["ip"], cmd, cfg["key"])
    try:
        raw = await washer_get(url)
    except Exception:
        new_ip = await _rediscover()
        if not new_ip:
            raise HTTPException(502, f"Cannot reach washer at {cfg['ip']} and re-discovery failed")
        cfg = load_config()
        raw = await washer_get(cc.write_url(new_ip, cmd, cfg["key"]))
    try:
        resp = cc.xor_decrypt(raw, cfg["key"])
        data = json.loads(resp)
    except Exception:
        data = {"raw_response": raw}
    global _last_status_time
    _last_status_time = 0
    return data


@app.post("/api/start")
async def start_programme(body: StartBody):
    cfg = load_config()
    if cfg.get("protocol") == "dual":
        raise HTTPException(400, "Use /api/dual-start for dual protocol")
    cmd = cc.wifible_start(**body.model_dump())
    return await send_command(cmd)


@app.post("/api/dual-start")
async def dual_start_programme(body: DualStartBody):
    cmd = cc.dual_start(**body.model_dump())
    return await send_command(cmd)


@app.post("/api/pause")
async def pause():
    cfg = load_config()
    if cfg.get("protocol") == "dual":
        raise HTTPException(400, "Dual protocol does not support pause")
    return await send_command(cc.wifible_pause())


@app.post("/api/resume")
async def resume():
    cfg = load_config()
    if cfg.get("protocol") == "dual":
        raise HTTPException(400, "Dual protocol does not support resume")
    return await send_command(cc.wifible_resume())


@app.post("/api/stop")
async def stop(prnm: int = Query(...)):
    cfg = load_config()
    if cfg.get("protocol") == "dual":
        return await send_command(cc.dual_stop(prnm))
    return await send_command(cc.wifible_stop(prnm))


# ---- Programmes ----

@app.get("/api/programmes")
def get_programmes():
    cfg = load_config()
    proto = cfg.get("protocol", "wifible")

    # Prefer real programmes from cloud (saved by get_key.py --save)
    if MY_PROGRAMMES_PATH.exists():
        progs = json.loads(MY_PROGRAMMES_PATH.read_text())
    else:
        data = load_programmes()
        if proto == "dual" and "washer_dryer_dual_demo" in data:
            progs = data["washer_dryer_dual_demo"]["programmes"]
        else:
            progs = data.get("washer_dryer_wifible_demo", {}).get("programmes", [])

    data = load_programmes()
    return {
        "protocol": proto,
        "programmes": progs,
        "option_bits": data.get("option_bits_OptMsk1", {}),
        "steam_values": data.get("steam_values", {}),
        "dry_values": data.get("dry_values_wifible", {}),
    }


# ---- Favourites ----

def _load_favourites() -> list:
    if FAVOURITES_PATH.exists():
        return json.loads(FAVOURITES_PATH.read_text())
    return []

def _save_favourites(favs: list):
    FAVOURITES_PATH.write_text(json.dumps(favs, indent=2))


class FavouriteBody(BaseModel):
    name: str
    prnm: int
    prcode: int
    settings: dict


@app.get("/api/favourites")
def get_favourites():
    return _load_favourites()


@app.post("/api/favourites")
def add_favourite(body: FavouriteBody):
    favs = _load_favourites()
    fav = {
        "id": f"fav_{int(time.time()*1000)}",
        "name": body.name,
        "prnm": body.prnm,
        "prcode": body.prcode,
        "settings": body.settings,
    }
    favs.insert(0, fav)
    _save_favourites(favs)
    return fav


@app.delete("/api/favourites/{fav_id}")
def delete_favourite(fav_id: str):
    favs = _load_favourites()
    favs = [f for f in favs if f["id"] != fav_id]
    _save_favourites(favs)
    return {"ok": True}


# ---- Probe (find the washer on the network) ----

@app.get("/api/probe")
async def probe(ip: str = Query(...), key: str = Query(...)):
    """Test if a washer is reachable and the key works."""
    url = cc.read_url(ip)
    try:
        raw = await washer_get(url, timeout=5.0)
    except Exception as e:
        return {"ok": False, "error": f"Cannot reach {ip}: {e}"}
    try:
        decoded = cc.decode_status(raw, key)
        return {"ok": True, "status": decoded}
    except Exception as e:
        return {"ok": False, "error": f"Key may be wrong: {e}"}


# ---- Discovery ----

@app.post("/api/discover")
async def discover_washer(timeout: float = Query(default=15.0, le=60.0)):
    """Listen for UDP broadcast from the washer and update config with its IP."""
    cfg = load_config()
    mac = cfg.get("mac")
    if not mac:
        raise HTTPException(400, "No MAC address in config — run get_key.py --save first")
    result = await discover_async(mac=mac, timeout=timeout)
    if not result:
        return {"ok": False, "error": f"No broadcast received within {timeout}s"}
    cfg["ip"] = result["ip"]
    save_config(cfg)
    return {"ok": True, "ip": result["ip"]}


@app.on_event("startup")
async def _auto_discover():
    """Verify cached IP or discover the washer if unreachable/missing."""
    cfg = load_config()
    if not cfg.get("key"):
        return
    if cfg.get("ip"):
        try:
            await washer_get(cc.read_url(cfg["ip"]), timeout=4.0)
            print(f"Washer reachable at {cfg['ip']}")
            return
        except Exception:
            print(f"Cached IP {cfg['ip']} unreachable — re-discovering...")
    mac = cfg.get("mac")
    if mac:
        print("No IP configured — listening for washer UDP broadcast (10 s)...")
        result = await discover_async(mac=mac, timeout=10.0)
        if result:
            cfg["ip"] = result["ip"]
            save_config(cfg)
            print(f"Auto-discovered washer at {result['ip']}")
            return
    print("Scanning LAN for washer...")
    ip = await lan_scan(cfg["key"], progress=lambda m: print(f"  {m}"))
    if ip:
        cfg["ip"] = ip
        save_config(cfg)
        print(f"Found washer at {ip}")
    else:
        print("Washer not found. Set the IP in the web UI or POST /api/discover.")


# ---- Serve frontend ----

@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8420)
