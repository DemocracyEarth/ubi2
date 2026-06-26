# Proof of Humanity — brand assets

The official Proof-of-Humanity mark + palette, used for **all proof-of-humanity / identity** surfaces
(the Identity section, the verified-human badge, the PoH NFT card) — distinct from the UBI-green money/
streams identity.

## Logo
- `apps/wallet/public/poh-logo.svg` — the full lockup: the **fingerprint-in-shield** mark (gradient-filled)
  + the "PROOF OF HUMANITY" wordmark.
- The mark itself is the path inside `mask#Mask_Mask_1` (the shield+fingerprint silhouette). For a
  mark-only badge / the on-chain NFT card, fill that path with the gradient below (drop the wordmark paths).

## Palette
| Token | Value | Use |
|---|---|---|
| PoH gradient start | `#FFFF00` (yellow) | the mark + PoH accents (gradient start) |
| PoH gradient end | `#FF6699` (pink) | the mark + PoH accents (gradient end) |
| PoH green | `#009966` | secondary PoH accent |
| white | `#FFFFFF` | wordmark / on dark |

Gradient (as in the logo): `linearGradient` from `#FFFF00` → `#FF6699`.

## Usage
- **On-chain PoH NFT card** (Rust, `crates/rpc`): a soulbound ERC-721 minted to each verified human;
  the card embeds the fingerprint mark filled with the yellow→pink gradient + "Proof of Humanity" +
  the human's address / verified date / vouches / reputation.
- **UI** (`apps/wallet`): the Identity section, the "Verified human" badge, vouch elements, and the PoH
  NFT use the gradient + the `poh-logo.svg` mark — so proof-of-humanity reads in the PoH brand, not the
  UBI-green brand.
