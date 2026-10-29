# Washer — Android app

A standalone Android app with the same features as the web app in [`../web`](../web): status,
start (wifible and dual), pause/resume, stop, favourites, connection test, and finding the washer
again by UDP broadcast or LAN scan. The phone talks to the washer directly over Wi-Fi; no PC or
server is needed.

## How it works

- The UI is [`../web/static/index.html`](../web/static/index.html), copied into the APK at build
  time, so UI changes to the web app carry over on the next build.
- [`bridge.js`](app/src/main/assets/bridge.js) is injected into that page. It sends the page's
  `fetch('/api/...')` calls to Kotlin instead of the Python server.
- `WasherApi.kt` ports `server.py`, `CandyCrypto.kt` ports `candy_crypto.py`, and `Net.kt` ports
  `discover.py`.
- Config and favourites are stored on the phone, entered on the app's settings screen.
- The programme list is the demo table for your protocol from `programmes.json`, unless the build
  includes your own list (see below).

## Build and install

Needs JDK 17+ and the Android SDK (platform 35). Set `sdk.dir` in `local.properties`.

```sh
./gradlew assembleRelease          # → app/build/outputs/apk/release/app-release.apk
adb install -r app/build/outputs/apk/release/app-release.apk
```

Or copy the APK to the phone and open it; Android will ask to allow installs from that source.
The APK is signed with the local debug key (`~/.android/debug.keystore`). Keep using the same
machine/key so updates install over the existing app and keep its settings.

### Building with your own washer's data

After running [`bootstrap.py --save`](../bootstrap.py), build with:

```sh
./gradlew assembleRelease -PwithLocalData
```

This also bundles `../web/my_programmes.json` (your washer's real programme list),
`../web/config.json` (IP, encryption key, MAC; seeds the settings on first launch) and
`../web/favourites.json`. **That APK contains your washer's key, so don't share it.** A build
without `-PwithLocalData` never includes these files.

## Tests

Tests for the protocol port (expected values from `candy_crypto.py`):

```sh
./gradlew testReleaseUnitTest
```
