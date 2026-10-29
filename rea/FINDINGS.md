# Candy Simply-Fi app: local washer-dryer API (static analysis)

Target: `candy_simplify.apk`, SHA-256 `35df93c6e0b5883bee8cb066ba8ef35d3ee4c5e2af164e3a6b02675821718b03`
App: `it.candy.simplyfi` version 3.14.1 (versionCode 226), release/prod build (`AndroidManifest.xml`, `it/candy/simplyfi/BuildConfig`).
Method: static analysis only. Nothing was run or installed, and no device or network host was contacted.

Confidence labels: **high** = read directly in code or data; **medium** = strongly implied by code but not shown end to end; **low** = educated guess. Anything marked *(inferred)* is not directly observed.

---

## 1. Summary

- **App type:** a native Android Java/Kotlin app (5 DEX files). There is no Flutter, React Native or Xamarin runtime. The three native libraries are third-party: `libTransform.so` (Huawei map coordinate conversion), `librealm-jni.so` (Realm database) and `libucs-credential.so` (Huawei SDK). None of the appliance logic is native, so Ghidra was not needed. **high**
- **Local API:** plain HTTP to the appliance on port 80.
  - `GET /http-read.json?encrypted=1` returns status.
  - `GET /http-write.json?encrypted=1&data=<HEX>` sends commands.
  - `GET /http-config.json?...` is used once, during pairing.
  - `GET /http-getStatistics.json` and `/http-prepareStatistics.json` return statistics. **high**
- **Encryption:** repeating-key XOR over the UTF-8 bytes of the parameter string, sent as upper-case hex. Replies are encrypted the same way. There is no IV, MAC or nonce, so this is obfuscation rather than real security. **high**
- **Key:** a **16-character per-appliance session key**. The app generates it during pairing and sends it to the washer as `ENCRYPT_KEY`. That pairing request is itself XOR'd with a key derived from the washer's own access-point SSID (last 8 characters, written twice).
  - The app then uploads the session key to Candy's cloud (`encryption_key` in `appliances.json`), and gets it back from the cloud on every login.
  - Because of a bug in the generator (`nextInt(14)`), keys only ever use the letters `a`–`n`. **high**
- **Two washer protocols exist.** Which one your machine uses depends on the `connectivity` value the cloud reports for it:
  - **"wifible"** (newer; `Washer`/`WasherDryer`): sends `PrNm, PrCode, PrStr, TmpTgt, SLevTgt, SpdTgt, OptMsk1, OptMsk2, Lang, Stm, Dry, ED, RecipeId, StartCheckUp, DispTestOn`. Pause is `Pa=1`, resume is `Pa=0`.
  - **"dual"** (older DualTech Wi-Fi+NFC): sends `Pa=0&Sel=0&PrNm, StSt or DelMd/DelVl, TmpTgt+TmpDf, SLevTgt, SpdTgt+SpdDef, OptMsk, Stm, Option, RecipeId, CheckUpState`. The app has no pause command for this protocol. **high**
- **Parameter names from the brief:** `Temp`, `SpinSp`, `Opt1`–`Opt9`, `DelVal`, `DryT` and `Steam` are **status (read) fields**, not write parameters. `DryLev` only exists in the tumble-dryer library. `StSt` and `PrCode` are write parameters. **high**
- **Programmes:** for a real appliance they are **downloaded from the cloud** (`appliances.json?with_programs=1`). The APK bundles only demo copies in `assets/candy_database.sql`, including two washer-dryers (one per protocol). Downloadable "recipe" programmes are app-only: they come from `wm_wd_programs.json` and are run as `RecipeId=D_<n>` on top of a parent knob programme. **high**
- **Cloud:** when the phone is away from home, every command goes through `POST https://simply-fi.herokuapp.com/api/v1/commands.json`, and status comes from `GET .../appliances/<id>.json`. This means the appliance itself holds a cloud connection *(inferred, high)*.
  - Even at home, the app **forwards each local status reading to `https://simplyfimgmt.candy-hoover.com/api/av1/listen.json`**. If the server replies with a `command`, the app **sends that command to the washer verbatim**. In other words, the phone relays server commands into your LAN. **high**
  - No firmware-update code exists in the app for washers. **high** (bounded search)

---

## 2. Tools and coverage

| Step | Tool | Result |
|---|---|---|
| Framework detection | `unzip -l`, DEX class index (own parser), REA `inspect_native_exports` | 5 DEX, 37,988 class defs, 7,044 in `it.candyhoover.*` (6,866 in `classes4.dex`). Native exports show only Huawei/Realm code (REA evidence `ev_57ac636f924dcabbcf6aa2ee4ccb5f05e42cc8efc774542221240ba536f3d402`). |
| Java decompile | JADX 1.5.6 CLI, one DEX at a time (`classes4`, `classes`, `classes2`, `classes3`) | A single full-APK run ran out of memory at 65% and left gaps, so it was redone per DEX. `classes4.dex` completed with 85 method-level errors, none in the classes cited here. REA's own JADX provider was unavailable (`REA_JADX_MCP_JAR` not configured). |
| Resources | `jadx --no-src` | 8,493 strings decoded; used for programme labels. |
| Bundled DBs | REA `inspect_sqlite_database` (evidence `ev_dcd44e0ce91c243966f23a2fb253ba6429b8476f561843d770efa32f14c43bea`, DB SHA-256 `7c11988d…5d4d`), plus read-only `sqlite3` for bulk export | |

All class paths below are relative to the JADX output, e.g. `it/candyhoover/core/...`.

---

## 3. Local API

### 3.1 Endpoints (all `http://<appliance-ip>/`, port 80)

| Endpoint | Purpose | Evidence |
|---|---|---|
| `http-read.json?encrypted=1` (or `=0`) | Status. The body is hex of XOR(JSON). | `washer/axibianca/services/status/StatusService` `@GET("http-read.json") getStatus(@Query("encrypted"))`; legacy `CandyWasher.getReadStatusUrl()` |
| `http-write.json?encrypted=1&data=<HEX>` | Every command | `washer/axibianca/services/CommandService` (`start/stop/checkup/resetCheckup/resetGoodNight`); `models/commands/CandyCommand.asGETString()` |
| `http-write.json?encrypted=0&k=v&...` | Unencrypted variant (debug toggle) | `CandyCommand.asGETString` (`?encrypted=0&` + params); `CommandService.formatLocalCall` |
| `http-config.json?encrypted=1&data=<HEX>` | Pairing (Wi-Fi credentials and session key). Sent to `192.168.0.1` while the phone is on the washer's access point. | `connectionmanager/ConnectionManager.configureAppliance`, `APPLIANCE_CONFIGURATION_IP="192.168.0.1"`; `washer/axibianca/services/enrollment/EnrollmentService` |
| `http-write.json` with `GetStat=1` | Statistics | `washer/axibianca/services/statistics/StatisticsService` (`xorEncrypt("GetStat=1", key)`) |
| `http-prepareStatistics.json?encrypted=1`, `http-getStatistics.json?encrypted=1` | Statistics (two steps) | same class |

- **Successful reply:** the plaintext is JSON containing `"response":"success"`. Writes are encrypted with the session key (`Washer.sendLocalCommand`, `ConnectionManager.sendCommandEncrypted`). **high**
- **After a successful start:** the app waits 3 s, then reads status again (`Washer.onCommandSendSuccessful`, `postDelayed(...,3000L)`). **high**
- **Throttling:** commands are queued; while a command is in flight, status polling is paused (`CandyAppliance.elaborateCommandsInQueue`, `sanityTimer`). **high**

### 3.2 Payload encoding and encryption (`it/candyhoover/core/classes/utilities/CandySecurityUtility`)

```
xorEncrypt(message, key) = HEX_UPPER( message.getBytes()[i] XOR key.getBytes()[i % key.length] )
xorDecrypt(hex, key)     = new String(decode16(hex)) then char-wise XOR with key
```

- **Plaintext format:** `k=v&k=v...`, joined with no URL-encoding (`CandyNetworkUtility.urlWithParams`; `Command.addParam` → `"&"+name+"="+value`). **high**
- **Request:** the hex goes in the `data` query parameter, next to `encrypted=1`. **high**
- **Reply:** the response body is the same scheme, encrypted with the same key. `LanScanner.checkIp` and `StatusService.getStatus` decrypt it with `xorDecrypt`. **high**
- **Decrypt quirk:** the app's `xorDecrypt` decodes the bytes as UTF-8 *before* XOR-ing. This is only correct for 7-bit ASCII. `candy_crypto.py` XORs raw bytes and also includes an app-identical variant. **high**
- **How encryption is chosen:** `CandyApplication.USE_ENCRYPTION = true`. A hidden button in `appliances/APP_01_HomeActivity` (`imagebuttonEnc`) toggles it. `CandyApplication.checkFlags()` throws `"NOT USE_ENCRYPTION"` if it is off at start-up. So the release app always encrypts. Whether the firmware still accepts `encrypted=0` is unknown. **high** for the app; firmware behaviour unknown.

### 3.3 The key: how it is created and used

| Key | Value | Used for | Evidence |
|---|---|---|---|
| **Configuration key** | Last 8 characters of the washer's access-point SSID (quotes removed; spaces become `$` except on Bianca/Axi/TFT/HWASH700 types), written twice. Example: AP `WIFIWASHMACHINE-xyzk` gives `INE-xyzkINE-xyzk`. | Encrypting the `http-config.json` pairing request | `CandySecurityUtility.calculateEncriptionKeyForConf`, `CandyStringUtility.cleanSSID`; placeholder AP names from `CandyWasher.pseudoNetwork()` = `WIFIWASHMACHINE-xyzk`, legacy `CANDYWASHMACHINE-xyzk`, `rootNetwork()` = `WIFIWASH` |
| **Session key** (`encryption_key`) | 16 random characters from `calculateEncriptionKey()` = `randomStringWithLength(16)`. That function uses `new Random(System.currentTimeMillis())` and `nextInt(length-2)` = `nextInt(14)` over `"abcd…"`, so **only `a`–`n` ever appear**. | Every later read and write; also used to decrypt the pairing reply | `CandySecurityUtility`; `NRLM_03_02_WifiSettingsSSID.trySendData`; `ConnectionManager.configureApplianceEncrypted` decrypts the reply with `__encriptionKey`. All 15 non-empty demo keys in `configured_appliances.encryption_key` match `^[a-n]{16}$`. |
| Startup key | First 8 SSID characters, written twice | No washer caller found | `CandySecurityUtility.getStartupKey` |

**Pairing request** (`ConnectionManager.configureAppliance`):

```
GET http://192.168.0.1/http-config.json?encrypted=1&data=HEX(XOR("NTW_MODE=<sec>&SSID=<home ssid>&PASSWORD=<pwd>&ENCRYPT_KEY=<session key>", configKey))
```

**Where the key is stored:**
- **Cloud:**
  - `POST /api/v1/appliances.json {appliance:{sixteen_digits_code, encryption_key, ssid_name, mac_address, ssid_security, purchase_date}}` (`createNewApplianceWithSerial`)
  - `PUT /api/v1/appliances/<id>.json {ssid_name, encryption_key, ssid_security}` (`updateApplianceWithSerial`)
  - On every sync the app reads it back from the server (`CandyAppliance.updateWithServerDictionary` → `setEncryptionKey(json "encryption_key")`).
- **Phone:** the local DB holds the key in `configured_appliances.encripted_key`, encrypted by `CandyCacheDataManager`. The plaintext `encryption_key` column is cleared by `Persistence.clearPlainKey`. **high**

**Answer to "fixed, derived, or obtained during pairing?"**
- The working key is **random and set during pairing**, with a weak generator: about 14^16 values in theory, but seeded from a millisecond timestamp, so it is guessable if the pairing time is roughly known *(inferred)*.
- It is **not** fixed and **not** derived from the serial or MAC.
- The pairing-step key **is** derived from the AP SSID.
- For your own app you can obtain the key in two ways:
  - **(a) Re-pair** the washer through `http-config.json` with a key you choose. This needs no cloud access, but the Candy app will then hold a stale key.
  - **(b) Read your existing key** from the Candy cloud account (`appliances.json` → `encryption_key`), or from the official app's database on a rooted phone.

### 3.4 Finding the appliance on the LAN (`it/haier/udp/*`)

- **UDP broadcast:** the app listens on **UDP port 55555** (`CandyUDPListener2.port`). It reads the ASCII text in bytes 60–92 of each packet, takes the MAC from `substring(1,13)`, uses the sender IP as the appliance IP, and matches it against the stored MAC. **high** for the code; the packet layout beyond these offsets is unknown.
- **LAN-scan fallback:** `LanScanner.checkIp` pings each host on the /24, then requests `http://<host>/http-read.json?encrypted=1`. `LanScan.foundIp` accepts the host whose reply XOR-decrypts (with the stored key) into valid JSON. **high**
- **Last known IP** is cached in `configured_appliances.ip` (`CandyDataManager.updateIpForAppliance`).

---

## 4. Commands

The full parameter table is in **`commands.json`**. The ready-made sequences below are implemented in `candy_crypto.py`.

### 4.1 Which protocol applies (`models/appliances/CandyApplianceFactory`)

| Cloud `type` | `connectivity` | Class | Protocol |
|---|---|---|---|
| washer_dryer | contains `dual` | `CandyWasherDryerDualTech` | **dual** (`CandyWasherDTCommand`) |
| washer_dryer | `wifible` | `washer/axibianca/model/WasherDryer` | **wifible** (`axibianca.model.command.Command`) |
| washer_dryer | anything else | `CandyWasherDryerNFC` | NFC only, no Wi-Fi API |

The demo DB contains one of each Wi-Fi kind: `GVFW 4118TWHC-47` (`3D_DUAL`, dual) and `ROW 4854DXH\1-S` (`RAPIDO_4DIG_STM`, wifible).

### 4.2 wifible: start with chosen settings (`Command.getParameterString`, `CommandService.start`)

```
Write=1&StSt=1&DelVl=<n>&PrNm=<selector>&PrCode=<pr_code>&PrStr=<name>&TmpTgt=<°C>&SLevTgt=<soil>
&SpdTgt=<rpm/100>&OptMsk1=<mask>&OptMsk2=<mask2>&Lang=<lang>&Stm=<steam>&Dry=<dry>&ED=<0|1>
&RecipeId=<0|D_n>&StartCheckUp=0&DispTestOn=1
→ GET http://<ip>/http-write.json?encrypted=1&data=HEX(XOR(that, key))
```

- `TmpTgt` is omitted when the temperature is not applicable (-1). `SpdTgt` is omitted when spin is 255.
- A delayed start still sends `StSt=1`, with `DelVl>0`.
- `Dry` is sent only if the appliance is a `WasherDryer` (`supportsDry`); otherwise `Dry=0`.
- `ED` is non-zero only on `_ad` (auto-dose) interfaces.

Example built from the demo washer-dryer's "Eco Cottons" (PrNm 11, PrCode 2) with cupboard drying:
`Write=1&StSt=1&DelVl=0&PrNm=11&PrCode=2&PrStr=Eco Cottons&TmpTgt=40&SLevTgt=3&SpdTgt=14&OptMsk1=0&OptMsk2=0&Lang=1&Stm=0&Dry=3&ED=0&RecipeId=0&StartCheckUp=0&DispTestOn=1` **high**

### 4.3 wifible: pause, resume and stop

| Action | Plaintext | Evidence |
|---|---|---|
| Pause | `encrypted=0&Pa=1` (the literal `encrypted=0&` is *inside* the encrypted payload) | `washer/axi/model/command/AxiPauseWasherCommand` (`addFirstParam(ENCRYPTED,0)`); `AbWasherHomeActivity.togglePause` |
| Resume | `encrypted=0&Pa=0` | `AbWasherHomeActivity.resumePause` |
| Stop | `Write=1&StSt=0&PrNm=<current PrNm from status>` plus `&DelVl=0` if a delayed start is armed | `washer/axibianca/model/command/StopCommand` |
| Resume after "good night" | `Write=1&RestartGN=1` | `ResetGoodNightCommand` |
| Check-up | `CheckUpState=1` (`StartCheckUp=1` on HWASH700); reset with `Write=1&StSt=0&PrNm=11` | `CheckupCommand`, `ResetCheckupCommand` |
| Auto-dose / hardness | `Write=1&SetDet=0|1&SetSoft=0|1` / `SetHard=<n>` | `AxiAutodoseWasherCommand`, `AxiSetHardnessWasherCommand` |

- **Pause availability:** pause is hidden for `bianca` interface types (`Washer.supportsPause`). **high**
- **Unencrypted path:** `getParametersMap()` for a start command **omits `Write=1`**, while the encrypted string includes it. This only matters if you use `encrypted=0`. **high**

### 4.4 dual: start, stop and reset (`CandyWasherCommand.getParameterString` + `CandyWasherDTCommand.getParameterString`)

```
Write=1&Pa=0&Sel=0&PrNm=<selector>&StSt=1                 (delay: &DelMd=1&DelVl=<n> instead of &StSt=1)
[&TmpTgt=<°C>&TmpDf=<default>]                             only if different from the default
[&SLevTgt=<soil>]                                          only if different (soil 1 at 90 °C is forced to 2)
[&SpdTgt=<rpm/100>&SpdDef=<default/100>]                   only if different
&OptMsk=<mask>&Stm=<steam>[&Option=<dry>]&RecipeId=<0|D_n>&CheckUpState=0
```

- `&Option=` is sent only for washer-dryers.
- For a dry-only programme, the temperature, soil and spin fields are skipped.
- **Stop:** `Write=1&StSt=0&DelMd=0&PrNm=<current Pr>` (`stopAsGETString`).
- **Reset after a finished cycle:** `Write=1&Sel=1PrNm=<Pr-1>`. Note the **missing `&`**, which is an app bug (`resetAsGETString`).
- **Pause:** not implemented for dual. **high**

### 4.5 Value tables (details in `commands.json`)

- **`OptMsk1` / `OptMsk`:** 1 prewash, 2 hygiene, 4 anti-crease, 8 good night, 16/32/64 extra rinse +1/+2/+3 (only one at a time; exclusion mask 112), 128 aquaplus.
  Evidence: `Washer.getOptions`, `CandyWasher.Washer3DOption*`, `CandyWasherDualTech.getOptionsExclusions`. **high**
- **`OptMsk2`:** 1 = zoom (shorter cycle). Allowed only if the programme's `available_options2 & 1` (`Program.canSetZoom`). **high**
- **`Stm`:** 0 none, 1 cotton, 2 mixed, 3 refresh, 5 on.
  The programme's `steam` parameter decides what you may send: 5 = on/off toggle, 4 = user picks 1–3, 1–3 = fixed value, 255 = steam-only programme (`Program.BIANCA_STEAM_LABEL_TO_VALUE_MAP`, `canSetOnOffSteam`, ...). **high**
- **`Dry` (wifible):** 0 none, 1 extra, 2 iron, 3 cupboard, 5/6/7/8 timed 120/90/60/30 min, 9 wool (`Program.BIANCA_DRY_LABEL_TO_VALUE_MAP`). **high**
- **`Option` (dual):** 0 none, 1 extra, **2 cupboard, 3 iron**, 4 cooldown, 5–8 timed, 9 wool (`CandyWasherDryerDualTech.dryWithValue`, `dryValuesWithKey`: ARMADIO→"2", STIRO→"3"). **medium.** This is the opposite of wifible for 2 and 3; see the open questions.
- **`SpdTgt`:** rpm ÷ 100 (`Command.speedParam`). **high**
- **`SLevTgt`:** 1–3; 0 means not applicable. **high**
- **`DelVl`:** number of 30-minute steps, 0–48. The delay picker `AbMaterialTimePicker` adds 1 per 30 minutes and caps at 48; `saveEndExit` adds `offsetHours*2`. **medium**
- **`Lang`:** from `assets/language_mapping/languages.json` (Bianca: it 0, en 1, fr 2, nl 3, pt 4, es 5, de 6, ru 7, ...). **high**

---

## 5. Programmes

- **For a real appliance:** downloaded from the cloud.
  - Request: `GET https://simply-fi.herokuapp.com/api/v1/appliances.json?with_programs=1` with header `Authorization: Bearer <token>`.
  - Response: each appliance has `programs[]`, and each programme has `command_parameters[]` entries of the form `{name, datatype, validation}`.
  - Parsed by `CandyWasherProgram.applyParameters` and `CandyWasherDryerProgram.applyParameters`; the URLs are in `connectionmanager/Constants`.
  - The token comes from `oauth/token` on the same host. **high**
- **Downloadable ("recipe") programmes:** `GET https://simply-fi.herokuapp.com/api/v1/wm_wd_programs.json?interface_type=Bianca` (Candy, wifible) or `red_devil` (Hoover), with the same bearer token (`ConnectionManager.downloadDTDownloadablePrograms`).
  - Each one names a `parent` output cycle. `ProgramHelper.parentToProgram` maps it to a programme on your machine via `assets/guidedwash/parentToProgram.json`.
  - The app sends it as `RecipeId=D_<position>`, using the parent's `PrNm` plus the recipe's own temperature, spin, steam and dry values. **high**
- **Bundled in the APK:** `assets/candy_database.sql` holds demo rows (table `demo.is_demo=1`, plus 35 demo appliances):
  - Washer-dryer **ROW 4854DXH** (wifible): 22 programmes.
  - Washer-dryer **GVFW 4118TWHC-47** (dual): 20 programmes.
  - 72 downloadable washer-dryer recipes in `dt_down_prog`.
  - All of these are exported to **`programmes.json`**, with English labels from `res/values/strings.xml`.
- **Other assets:** `assets/assisted/washer_dryer.json`, `assets/guidedwash/*.json` and `assets/voicecontrol/alg/output_wd_*.csv` map fabric, colour, soil and dryness choices to output cycle, temperature, spin and dry type for the "assisted wash" and voice features. They pick programmes; they do not define new wire values. **high**

**Programme parameters** (from `CandyWasherProgram.applyParameters`):
- `selector_position` becomes `PrNm`; `pr_code` becomes `PrCode`.
- Other fields: `default/maximum_temperature`, `default/maximum_spin_speed`, `default/minimum/maximum_soil_level`, `available_options`, `available_options2`, `steam`, `dry`, `drying_type`, `program_type`/`program_type2` (W, D, WD, S), `default_duration` and `remaining_time_*`.
- Washer-dryers also have `av0`, `av1`, `av2` and `selector_position_dry` (`CandyWasherDryerProgram`); their meaning is unknown.
- A value of 255 means "not applicable / not adjustable".

**Programmes the app can select that are probably not on the knob** (also flagged in `programmes.json`):

| Programme | Why | Confidence |
|---|---|---|
| All 72 downloadable recipes (`RecipeId=D_n`) | App-only by design | high |
| "Refresh Touch" (`DUAL_WM_WD_PROGRAM_NAME_TUMBLING`, PrNm 16) | Offered as post-cycle anti-crease tumbling (`Washer.getTumbling`, `AbWasherHomeActivity`) | medium |
| "Auto-Clean" (`…_AUTOCLEAN`, PrNm 19, wifible) | Started from the maintenance screen (`Command.getMaintenanceCommand`) | medium |
| wifible PrNm ≥ 17 (Hygiene 60°, Baby 60°, Intensive 40°, Wash & Dry 59') and dual PrNm ≥ 16 (Silk, Daily 59') | Probably beyond the physical dial; the dial size of your model is unknown | low |
| dual PrNm 15 `SMART_FI_PLUS` (label resource reads "Auto-Clean") | Probably the knob's "Smart Fi+" slot | low |

Several entries share one `PrNm` and differ by soil level: wifible Saving 14'/30'/44' (PrNm 6) and dual Rapid 14/30/44 (PrNm 5). They are one knob position with variants selected by `SLevTgt` and `PrCode` (`Washer.getProgram`). **high**

---

## 6. Status fields

**Response shape:**
- **Local:** `{"statusLavatrice": {...}}` (`CandyWasherStatus.statusWithResponse`, `getStatusKey()="statusLavatrice"`).
- **Cloud:** `{"appliance": {"current_status_parameters": {...}, "additional_info": {"FillR": ...}}}`.
- No washer-dryer-specific key exists; washer-dryers use the same object. **high**

| Field | Meaning | Evidence / confidence |
|---|---|---|
| `WiFiStatus` | 1 = remote control enabled on the appliance; 0 = read-only | `CandyWasher.updateWithStatus` sets `readonly = !WiFiStatus` (high) |
| `Err` | Error code, compared as hex (`intValueFailToHex`); text in `assets/errors_<lang>.json` and DB `error_code` | high |
| `MachMd` | Machine mode: 0 none, 1 selection, 2 running, 3 paused, 4 delay set (selection), 5 delay counting, 6 error, 7 finished. "Active" = 2..5. | `CandyWasher.WasherStatus*` constants (high) |
| `Pr` / `PrNm` | Current programme selector position (wifible prefers `PrNm`) | high |
| `PrCode` | Current programme code (wifible) | `Washer.updateWithStatus` (high) |
| `PrPh` | Phase: 0 none, 1 prewash, 2 wash, 3 rinse, 4 last rinse, 5 end, 6 drying, 7 error, 8 steam, 9 good-night pause, 255 n/a | `CandyWasher.WasherPhase*`, `Washer.WasherPhaseSteam=8` (high) |
| `SLevel` | Soil level | high |
| `Temp` | Temperature setting, °C | high |
| `SpinSp` | Spin speed. Values under 100 are hundreds of rpm (`getSpinSpeed`: `i<100 ? i*100 : i`). | high |
| `DelVal` | Delay value. Shown as **minutes** (`AbWasherHomeViewModel.establishedTimeText`: `delay*60` s). | medium (unit conflicts with the command side) |
| `RemTime` | Remaining time, **seconds** *(inferred: the app sets `remainingTime = duration*60`; UI divides by 60)* | medium |
| `Opt1`…`Opt8` | One flag per option bit (Opt1 = prewash … Opt8 = aquaplus) | `updateWithStatus` loop (high) |
| `Opt9`…`Opt16` | Second option group. The app's loop shifts by `(n-1)`, so Opt9 lands on value 256, which is the app's "Zoom" constant `Washer3DOptionZoom=256`. | medium |
| `Lang` | Display language index | high |
| `CheckUpState` | Check-up state: 0 none, 1 running, 2 ended | high |
| `DisTestOn`, `DisTestRes` | Self check-up result: 0 not run, 1 OK, 2 failed | `Washer.SELF_CHECKUP_*` (high) |
| `RecipeId` | `0` or `D_<n>` for a running downloadable programme | high |
| `DryT` | Current dry type (same values as `Dry`) | medium |
| `Steam` | Current steam setting | high |
| `rED` | Extra dose | high |
| `Det`, `Soft`, `WaterHard`, `DetWarn`, `DetPreW`, `DPrgCnt`, `SoftWarn`, `SoftPreW`, `SPrgCnt` | Auto-dose state, warnings and counters | `WasherStatus` constants, `CandyWasher.updateWithStatus` (high) |
| `FillR` | Fill ratio (cloud only, in `additional_info`) | high |
| `rtA..rtD`, `rtaA..rtaD`, `rtwA..rtwD`, `rtr` | "Zelig" detergent-tank system fields | high (names); meaning medium |
| `chartL`, `motS`, `NtcD`, `NtcW`, `T0R`, `T0W`, `TIW`, `unbC`, `unbF`, `numF`, `APSfreq`, `APSoff` | Named in `WasherStatus`: chart line, motor speed, dry and wash NTC thermistors, unbalance compensated/factor, water fill count, APS frequency/offset | names high; units unknown |
| `MachMd`/`PrPh` = 7 | Triggers the "washing completed" message; dismissing it sends a reset (dual) | high |

---

## 7. Cloud and remote control

### 7.1 Remote hosts

Collected from DEX strings, `resources.arsc`, assets and code. Relevant ones:

| Host | What is sent | Evidence |
|---|---|---|
| `checkip.amazonaws.com` | Plain HTTP lookup of the home's public IP, which is then sent to `outdoor_enrolment/start` with the session key | `connectionmanager/IpChecker`, `NRLM_04_01_CheckNetworkHomeActivity` |
| `simply-fi.herokuapp.com` (main API, `BuildConfig.BASE_URL`) | OAuth login (`oauth/token`, `api/v1/users.json`, `me.json`). Appliance records: serial, MAC, SSID name, security, **session key**. Programme lists. **Remote commands** (`POST api/v1/commands.json {appliance_id, body:"<plaintext param string>"}`). Remote status (`GET appliances/<id>.json`). Statistics, ratings, warranties, error codes, push-device registration. | `connectionmanager/Constants`, `ConnectionManager`, `CommandService`, `StatusService`. Headers: `Authorization: Bearer`, `Salesforce-Auth: 1`, `App-Version-*` (`BaseService.getOkHttpClient`). |
| `simplyfimgmt.candy-hoover.com` | **Status forwarding**: `GET api/av1/listen.json?encrypted=1&macAddress=<mac>&data=HEX(XOR(status-as-query-string + macAddress + forwarded=android, key))`. The reply is decrypted with the appliance key; if it contains `command`, that string is sent to the washer locally (`ForwardCommand`). | `StatusService.handleStatusResponse/forwardStatus`, `Washer.onStatusForwardToCandySuccess`, `BuildConfig.STATE_FORWARD_URL` |
| `go.he.services`, `api-iot.he.services` | Zelig / promo services | `ZeligHelper`, `PromoService` |
| `*.execute-api.*.amazonaws.com`, `iotbeplatform.auth.eu-west-1.amazoncognito.com`, `simplyfi-prod.s3*` | Zelig tank codes, Click&Wash, app-log upload, assets | `BuildConfig`, `S3LogToken`, `clickwash/*` |
| `api.openweathermap.org` | Weather for the delay-start suggestion (uses location) | `washer/axibianca/utils/WeatherUtils` |
| `dialogflow.googleapis.com`, `api.api.ai` | Chatbot / voice | `it/candy/common/bot/DataService*` |
| `login.salesforce.com` | User account | `salesforce/SalesforceHelper` |
| Firebase / Crashlytics, Flurry, Facebook, Google, Amazon (Login with Amazon, Dash Replenishment), Huawei HMS (dbankcloud / hicloud) | Analytics, crash logs, sign-in, auto-replenishment, push/location on Huawei | SDK classes; `assets/app.properties` (Flurry key), `assets/grs_sdk_*` |
| `simplyfiservice.candy-hoover.com`, `wizardservice.candy-hoover.com` | FAQ, manuals, contact web pages | `classes/CandyConstants` |

### 7.2 How the app chooses local or cloud

`CandyNetworkUtility.isLocalNetwork`:
- **Local** if the phone is on Wi-Fi *and* the current SSID equals the home SSID saved at pairing, or the SSID starts with an appliance AP prefix (`WIFIWASH...`). Demo mode and `forceLocal` also count as local.
- **Cloud** if the phone is on mobile data, the SSID differs, or the SSID is unknown.
- Each service additionally requires a valid stored IP (`BaseService.canUseLocal`).
- When local, requests go to `http://<ip>/…`; otherwise to `simply-fi.herokuapp.com`. **high**

### 7.3 Remote commands and firmware

- **The appliance accepts commands that originate in the cloud.** **high**
  - When away, the app POSTs the plaintext command to the cloud (`commands.json`), and the washer starts.
  - This means the washer keeps its own connection to Candy's backend and receives commands from it *(inferred, high; the appliance side is not in the APK)*.
- **The phone also relays server commands into your LAN.** **high**
  - Every local status read is forwarded to `listen.json`.
  - Any `command` in the reply is sent verbatim to `http-write.json` via `ForwardCommand`.
  - The server can do this because it knows each appliance's key.
- **Outdoor enrolment.** If the washer is not found on the LAN after pairing (both UDP and LAN scan fail), the app falls back to the cloud. **high**
  - It looks up the home's **public IP** from `http://checkip.amazonaws.com` (`connectionmanager/IpChecker`).
  - It then calls `POST /api/v1/outdoor_enrolment/start?ip=<public ip>&encryption_key=<session key>` and polls `/api/v1/outdoor_enrolment/listen?...` (`NRLM_04_01_CheckNetworkHomeActivity.applianceNotFound` → `startOutdoorEnrolment`; `ConnectionManager.outdoorEnrolmentStart/Result`).
  - This implies the washer connects to Candy's cloud on its own and is identified there by public IP and session key *(inferred, high)*.
- **Firmware updates:** no washer firmware or OTA code was found in the app. A bounded search for `firmware|ota|fwver|upgrade` across `it.*` packages hit only oven `FWver` status and database upgrade helpers. Whether the appliance updates itself from the cloud cannot be determined from the APK.
- **Privacy:** pairing logs include the session key, SSID and plaintext commands (`[connmng]`, `[command]` tags through `CNYLog`). `CNYLog.logMessage` writes to a local file and to `FirebaseCrashlytics.log`. Crashlytics breadcrumbs are uploaded with crash reports *(inferred, medium)*.
- **Hard-coded secrets:** the APK contains OAuth client credentials (`Constants.OAUTH_CLIENT_ID/SECRET`) and AWS Cognito client IDs (`BuildConfig.ZELIG_LOGGER_*`). They are not reproduced here and are not needed for local control.

---

## 8. Open questions

1. **Which protocol is your washer-dryer?** The cloud record's `connectivity` (`wifible` or `dual`) and `interface_type` decide it, and that record is not in the APK.
   - Model names in the bundled demos: `ROW…`/`RO…` are wifible, `GVF…` is dual.
   - Without the cloud: try a read with your key and look at the fields. The wifible code reads `PrNm`/`PrCode` (falling back to `Pr`); the dual code reads only `Pr`. That suggests which fields each firmware sends *(inferred, medium)*.
2. **Dry values 2 and 3 conflict.**
   - wifible: 2 = iron, 3 = cupboard (`Program.BIANCA_DRY_LABEL_TO_VALUE_MAP`, `AIDryerType`).
   - dual: 2 = cupboard, 3 = iron (`CandyWasherDryerDualTech`).
   - Test both on your machine.
3. **Delay units.** Commands use 30-minute steps (picker logic), but the status `DelVal` is displayed as minutes. Either the firmware converts between them, or one side of the app is wrong.
4. **`RemTime` units** are assumed to be seconds.
5. **Does the firmware still accept `encrypted=0`?** The release app never sends it.
6. **UDP 55555 broadcast:** what triggers it, how often it is sent, and the full packet layout. Only bytes 60–92 are parsed.
7. **`DispTestOn=1`** is always sent with start commands; its purpose is unknown. The meaning of `av0`–`av2` and `selector_position_dry` in washer-dryer programmes is also unknown.
8. **Re-pairing:** would changing the key through `http-config.json` break the official app and cloud? Very likely yes, until the cloud record is updated *(inferred)*. It is also not confirmed that `http-config.json` is reachable on the home network, rather than only on the washer's own access point.
9. **Your machine's real programme list** may differ from the demo tables. The authoritative source is your cloud account's `appliances.json?with_programs=1` (one authenticated request), or reading `PrNm`/`PrCode` from status while turning the knob.
10. **Cloud-relay safety:** if you keep the Candy app installed and on your home Wi-Fi, it will keep forwarding status and relaying cloud commands. Remove it, or block `simplyfimgmt.candy-hoover.com`, if you want local-only control. Whether the washer's own cloud link can be cut without side effects (for example `WiFiStatus`/remote enable) is unknown.

---

## 9. Deliverables

- `commands.json`: every writable parameter, its values, which protocol it belongs to, and its evidence; full start, pause, resume and stop sequences.
- `programmes.json`: demo washer-dryer programme tables (wifible and dual), 72 downloadable recipes, value legends and knob flags.
- `candy_crypto.py`: XOR/hex encrypt and decrypt, pairing-key derivation, command and URL builders for both protocols, and a status decoder. Its self-test uses the demo keys and programmes from the APK and makes no network calls (`python3 candy_crypto.py`).
