# Physical iOS and Android holder-vault drill

This procedure captures the remaining **physical-device** evidence for the production-disabled Proof of Humanity
holder vault. Simulator, emulator, desktop responsive mode and automated Chromium runs are useful regression lanes,
but none may be recorded as physical evidence.

## Preconditions

- Use a dedicated test device and a fresh testnet-only credential account. Never use a personal payment account.
- Serve the reviewed commit over HTTPS with `NEXT_PUBLIC_V2_HOLDER_VAULT_TESTNET_ENABLED=true` and
  `NEXT_PUBLIC_SELF_ENV=staging`.
- Confirm the UI says `audit admission: closed` and `product admission: closed`.
- Use only public testnets. Do not configure a mainnet PoH address or production Self environment for this drill.
- Confirm the device/browser supports WebAuthn PRF with a real platform or roaming authenticator.
- Prepare a second enrolled/synced passkey before any site-data clearing step.
- Do not screen-record, screenshot, paste into chat, log or commit the recovery key. Evidence may contain only the
  device model, OS/browser versions, sanitized result booleans and a one-way account label.

## Run once on physical iOS and once on physical Android

1. Open the HTTPS staging origin in Safari (iOS) or Chrome (Android) and install it to the home screen.
2. Launch the standalone PWA, connect the dedicated account and acknowledge the account-privacy guidance.
3. Enroll a passkey. Confirm the vault returns to `locked`; unlock it and confirm the summary is explicitly a
   non-production rehearsal.
4. Add a second passkey. Confirm the count increments once and the vault relocks.
5. Download the encrypted backup. Move the recovery key to a separate trusted channel, then hide it in the PWA.
6. **Cancellation:** start an unlock, cancel from the product button before completing the authenticator prompt,
   and confirm the vault remains locked. Cancel the native prompt too if it remains visible.
7. **Crash/restart:** unlock, force-terminate the installed PWA from the OS task switcher, relaunch from the home
   screen, reconnect/acknowledge the same account and confirm the durable vault is present but locked.
8. **Account invalidation:** unlock, switch the wallet to a different account, and confirm the old summary/recovery
   material disappears. Switch back, re-acknowledge, and confirm a fresh passkey assertion is required.
9. **Recovery:** only after verifying the encrypted package and second passkey are available, clear site data on
   this dedicated test device (or use a second fresh physical device). Reinstall/open the PWA, connect the original
   account, select the encrypted package, enter the recovery key, and confirm empty-only restore succeeds. Unlock
   with an enrolled/synced passkey. Confirm a second restore cannot overwrite the occupied vault.
10. Inspect browser site storage: the hashed database name and encrypted vault may exist; recovery key, PRF output,
    rehearsal plaintext, account address in the database name, and Cache Storage entries must not.

Clearing site data is destructive. Do it only on the dedicated test profile after the backup and a usable enrolled
passkey have been independently checked. The encrypted backup does not recover a lost passkey.

## Sanitized evidence record

Record one JSON object per platform outside the secret-bearing device, then review before committing:

```json
{
  "schema": "org.proofofhumanity.v2-holder-pwa-physical-device-evidence/1",
  "productionEligible": false,
  "physical": true,
  "simulatorOrEmulator": false,
  "platform": "ios-or-android",
  "deviceModel": "public model name only",
  "osVersion": "public version only",
  "browserVersion": "public version only",
  "reviewedCommit": "40 lowercase hex",
  "stagingOriginSha256": "64 lowercase hex",
  "observedAt": "RFC3339 UTC",
  "checks": {
    "installedStandalone": true,
    "nativePrfEnrollmentUnlock": true,
    "secondPasskeyAtomic": true,
    "cancellationRelocked": true,
    "forceTerminateRestartRelocked": true,
    "accountSwitchInvalidated": true,
    "emptyOnlyRestoreUnlockedWithPasskey": true,
    "occupiedRestoreRejected": true,
    "cacheStorageEmpty": true,
    "secretPersistenceNotObserved": true
  },
  "secretMaterialIncluded": false
}
```

Any false/missing check, simulator flag, unreviewed commit, production-enabled UI, secret material or recovery without
a passkey is a failed drill. Keep both production admission bits false after successful physical evidence; independent
browser/cryptographic audits remain separate gates.
