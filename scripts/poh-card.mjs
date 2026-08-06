// PoH NFT card generator — the reference template for the on-chain (Solidity + Rust) port.
// renderCard(traits) -> a self-contained SVG string. viewBox 640x900.
import { writeFileSync } from "node:fs";

const HEAD_PATH =
  "M 347.25 181.1 Q 347.25 147.05 334.2 115.65 321.15 84.2 297.1 60.15 273.05 36.05 241.6 23 210.15 10 176.15 9.95 174.897265625 9.9517578125 173.65 9.95 172.40078125 9.9517578125 171.15 9.95 137.1 10 105.65 23 74.25 36.05 50.2 60.15 26.1 84.2 13.1 115.65 0.05 147.05 0 181.1 0.0033203125 182.2296875 0 183.35 0.001953125 184.7263671875 0 186.1 0.05 203.45 4.5 220.25 8.9 237.1 17.4 252.25 25.9 267.4 37.9 279.95 49.95 292.5 64.75 301.65 L 79.75 310.85 79.75 418.7 Q 79.75 420.75 81.2 422.2 82.7 423.65 84.75 423.65 L 242.6 423.65 Q 244.65 423.65 246.1 422.2 247.6 420.75 247.6 418.7 L 247.6 377.15 295.75 377.15 Q 300.7 377.15 305.3 375.25 309.85 373.35 313.4 369.85 316.9 366.35 318.8 361.75 320.7 357.2 320.7 352.25 L 320.7 304.05 351.1 304.05 Q 355.5 304.05 359.45 302.05 363.4 300 365.95 296.45 368.5 292.85 369.2 288.5 369.5890625 285.8658203125 369.2 283.3 369.8205078125 279.015625 368.4 274.95 L 347.25 212.2 347.25 181.1 M 332.3 218 Q 332.3 218.85 332.55 219.6 L 353.95 283.1 Q 353.980859375 283.1904296875 354 283.25 353.620703125 284.544140625 352.85 285.65 351.7 287.25 349.9 288.2 348.2853515625 289.007421875 346.5 289.05 L 310.7 289.05 Q 308.65 289.1 307.15 290.55 305.75 292 305.7 294.05 L 305.7 347.55 Q 305.6390625 350.3458984375 304.55 352.95 303.4 355.7 301.35 357.8 299.25 359.9 296.5 361.05 293.8935546875 362.1400390625 291.05 362.2 L 237.6 362.2 Q 235.55 362.2 234.05 363.65 232.6 365.1 232.6 367.2 L 232.6 408.7 94.75 408.7 94.75 303.05 Q 94.75 301.75 94.1 300.65 93.45 299.5 92.35 298.8 L 74.95 288.15 Q 61.25 279.65 50.1 268.05 38.95 256.45 31.1 242.4 23.2 228.35 19.1 212.75 15.2994140625 198.1578125 14.95 183.05 15.5302734375 152.651171875 27.25 124.4 39.5 94.8 62.2 72.15 84.85 49.45 114.45 37.2 142.941796875 25.38046875 173.65 24.9 204.35625 25.38046875 232.8 37.2 262.45 49.45 285.1 72.15 307.75 94.8 320.05 124.4 331.76171875 152.7470703125 332.3 183.3 L 332.3 218 M 234.25 188.1 Q 234.25 186.15 232.9 184.75 231.5 183.4 229.6 183.35 L 229.25 183.35 Q 227.8 183.45 226.65 184.35 L 176.7 222.2 126.8 184.3 Q 125.9 183.6 124.75 183.4 123.65 183.2 122.55 183.5 121.45 183.85 120.6 184.65 119.8 185.4 119.4 186.5 119.05 187.6 119.2 188.7 119.4 189.85 120.05 190.8 L 172.85 266.35 Q 173.5 267.3 174.55 267.8 175.55 268.35 176.7 268.35 177.85 268.35 178.9 267.8 179.95 267.3 180.6 266.35 L 233.35 190.85 Q 234.25 189.65 234.25 188.1 M 174.4 77.35 Q 173.3 77.95 172.65 79.05 L 123.9 160.15 Q 123 161.75 123.3 163.5 123.65 165.25 125.05 166.35 L 173.85 203.95 Q 175.1 204.95 176.7 204.95 178.3 204.95 179.6 203.95 L 228.35 166.35 Q 229.8 165.25 230.1 163.5 230.45 161.75 229.55 160.15 L 180.75 79.05 Q 180.1 77.95 179.05 77.35 177.95 76.75 176.7 76.75 175.45 76.75 174.4 77.35 M 176.75 136.45 Q 177.6 136.45 178.4 136.8 L 219.8 155.55 Q 221.35 156.25 221.9 157.85 222.5 159.4 221.8 160.95 221.15 162.45 219.55 163.05 217.95 163.65 216.45 162.95 L 178.2 145.65 Q 177.5 145.3 176.7 145.3 175.95 145.3 175.25 145.65 L 137 162.95 Q 135.5 163.65 133.85 163.1 132.3 162.5 131.6 160.95 130.9 159.4 131.5 157.85 132.1 156.25 133.65 155.55 L 175.05 136.8 Q 175.85 136.45 176.75 136.45 Z";

// XML-escape interpolated text (defensive; the on-chain port must do the same).
const esc = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// A green check tick (distinct from the gold/pink brand accents) centred at (cx,cy).
const tick = (cx, cy, r = 13) =>
  `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="url(#ok)" stroke-width="1.6"/>` +
  `<path d="M${cx - 6} ${cy} l4 4 l8 -8.5" fill="none" stroke="url(#ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`;

// One attribute row: icon + label (left), value + green tick (right).
function row(cy, icon, label, value, valueFill) {
  const top = cy - 26;
  return (
    `<rect x="52" y="${top}" width="536" height="52" rx="15" fill="#0D0D12" stroke="url(#g)" stroke-opacity="0.20"/>` +
    icon(cy) +
    `<text x="116" y="${cy + 6}" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="#EAEAEE">${esc(label)}</text>` +
    `<text x="524" y="${cy + 6}" text-anchor="end" font-family="Helvetica,Arial,sans-serif" font-size="18" fill="${valueFill}">${esc(value)}</text>` +
    tick(558, cy)
  );
}

// Icons (gold), vertically centred on the row.
const globe = (cy) =>
  `<circle cx="84" cy="${cy}" r="12" fill="none" stroke="url(#g)" stroke-width="1.5"/>` +
  `<ellipse cx="84" cy="${cy}" rx="5" ry="12" fill="none" stroke="url(#g)" stroke-width="1.5"/>` +
  `<line x1="72.5" y1="${cy}" x2="95.5" y2="${cy}" stroke="url(#g)" stroke-width="1.5"/>` +
  `<line x1="75.5" y1="${cy - 6}" x2="92.5" y2="${cy - 6}" stroke="url(#g)" stroke-width="1.2" stroke-opacity="0.75"/>` +
  `<line x1="75.5" y1="${cy + 6}" x2="92.5" y2="${cy + 6}" stroke="url(#g)" stroke-width="1.2" stroke-opacity="0.75"/>`;

const shield = (cy) =>
  `<path d="M84 ${cy - 13} l11 4 v7 q0 9 -11 15 q-11 -6 -11 -15 v-7 z" fill="none" stroke="url(#g)" stroke-width="1.5" stroke-linejoin="round"/>` +
  `<path d="M79 ${cy - 1} l3.5 3.5 l6 -7" fill="none" stroke="url(#g)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>`;

const person = (cy) =>
  `<circle cx="84" cy="${cy - 5}" r="5.5" fill="none" stroke="url(#g)" stroke-width="1.5"/>` +
  `<path d="M73 ${cy + 11} q11 -13 22 0" fill="none" stroke="url(#g)" stroke-width="1.5" stroke-linecap="round"/>`;

export function renderCard(t) {
  const rows =
    row(602, globe, "Nationality", `${t.flag} ${t.nationality}`, "#F2F2F4") +
    row(664, shield, "Legal age", t.age, "url(#g)") +
    row(726, person, "Gender", t.gender, "url(#g)");

  return `<svg width="640" height="900" viewBox="0 0 640 900" xmlns="http://www.w3.org/2000/svg" role="img"><title>Proof of Humanity</title>
<defs>
<linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FFE24B"/><stop offset="52%" stop-color="#FF9A55"/><stop offset="100%" stop-color="#FF6B8A"/></linearGradient>
<linearGradient id="ok" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#6EE7B7"/><stop offset="100%" stop-color="#22C55E"/></linearGradient>
<linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#101016"/><stop offset="100%" stop-color="#08080B"/></linearGradient>
<radialGradient id="glow" cx="50%" cy="40%" r="42%"><stop offset="0%" stop-color="#FF7A66" stop-opacity="0.15"/><stop offset="100%" stop-color="#000000" stop-opacity="0"/></radialGradient>
</defs>
<rect width="640" height="900" fill="#000000"/>
<rect width="640" height="900" fill="url(#glow)"/>
<path d="M54 24 H562 L616 78 V846 A30 30 0 0 1 586 876 H54 A30 30 0 0 1 24 846 V54 A30 30 0 0 1 54 24 Z" fill="url(#card)" stroke="url(#g)" stroke-width="2"/>
<path d="M70 58 L74 74 L90 78 L74 82 L70 98 L66 82 L50 78 L66 74 Z" fill="url(#g)" opacity="0.9"/>
<text x="584" y="62" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="11" letter-spacing="3" fill="#C9A24E">TOKEN ID</text>
<text x="584" y="86" text-anchor="end" font-family="ui-monospace,Menlo,monospace" font-size="16" fill="#E8E8EC">${esc(t.tokenId)}</text>
<text x="54" y="156" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="56" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Proof of</text>
<text x="54" y="212" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="56" font-weight="800" letter-spacing="-1.5" fill="#F5F5F7">Humanity</text>
<text x="56" y="250" font-family="Helvetica,'Helvetica Neue',Arial,sans-serif" font-size="23" font-weight="600" fill="url(#g)">Verified with Self</text>
<circle cx="320" cy="400" r="120" fill="none" stroke="url(#g)" stroke-opacity="0.30" stroke-width="1" stroke-dasharray="1.5 7"/>
<circle cx="200" cy="400" r="3.5" fill="url(#g)"/>
<circle cx="440" cy="400" r="3.5" fill="url(#g)"/>
<circle cx="320" cy="400" r="94" fill="#0B0B10" stroke="url(#g)" stroke-opacity="0.55" stroke-width="1.5"/>
<g transform="translate(269,340) scale(0.276)"><path fill="url(#g)" d="${HEAD_PATH}"/></g>
<line x1="64" y1="556" x2="212" y2="556" stroke="url(#g)" stroke-opacity="0.4"/>
<line x1="428" y1="556" x2="576" y2="556" stroke="url(#g)" stroke-opacity="0.4"/>
<text x="320" y="561" text-anchor="middle" font-family="Helvetica,Arial,sans-serif" font-size="12" letter-spacing="5" fill="#C9A24E">DISCLOSED ATTRIBUTES</text>
${rows}
<rect x="52" y="768" width="536" height="64" rx="16" fill="#100C0E" stroke="url(#g)" stroke-opacity="0.32"/>
<path d="M92 786 l14 5 v9 q0 11 -14 19 q-14 -8 -14 -19 v-9 z" fill="none" stroke="url(#g)" stroke-width="1.6" stroke-linejoin="round"/>
<path d="M85 801 l4.5 4.5 l8 -9" fill="none" stroke="url(#g)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
<text x="122" y="795" font-family="Helvetica,Arial,sans-serif" font-size="17" font-weight="700" fill="#F5F5F7">Verified · Privacy Preserved</text>
<text x="122" y="817" font-family="Helvetica,Arial,sans-serif" font-size="13" fill="#8A8A92">Zero-Knowledge Proof</text>
<circle cx="548" cy="800" r="17" fill="none" stroke="url(#ok)" stroke-width="1.6" stroke-dasharray="2 4"/>
<path d="M540 800 l5 5 l10 -11" fill="none" stroke="url(#ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M70 852 l9 14 l-9 5 z" fill="url(#g)" opacity="0.85"/><path d="M70 852 l-9 14 l9 5 z" fill="url(#g)" opacity="0.55"/>
<text x="96" y="862" font-family="Helvetica,Arial,sans-serif" font-size="12" letter-spacing="0.4" fill="#C9A24E">${esc(t.chain)}</text>
</svg>`;
}

// ---- variants ----
const VARIANTS = [
  { file: "card", tokenId: "0x7A3F…C9E2", flag: "🇦🇷", nationality: "Argentina", age: "Over legal age", gender: "Female", chain: "Ethereum · EVM Compatible · Soulbound" },
  { file: "card-us", tokenId: "0x1B9C…4F0A", flag: "🇺🇸", nationality: "United States", age: "21 or older", gender: "Male", chain: "Base · EVM Compatible · Soulbound" },
  { file: "card-jp", tokenId: "0x0C4E…A7B2", flag: "🇯🇵", nationality: "Japan", age: "Over legal age", gender: "Other", chain: "Optimism · EVM Compatible · Soulbound" },
  { file: "card-ke", tokenId: "0xE20D…5F19", flag: "🇰🇪", nationality: "Kenya", age: "18 or older", gender: "Male", chain: "Celo · EVM Compatible · Soulbound" },
  { file: "card-de", tokenId: "0x9AF1…3C8D", flag: "🇩🇪", nationality: "Germany", age: "Over legal age", gender: "Female", chain: "UBI Chain · Native · Soulbound" },
];

if (import.meta.url === `file://${process.argv[1]}`) {
  const outDir = process.argv[2] || ".";
  for (const v of VARIANTS) {
    writeFileSync(`${outDir}/${v.file}.svg`, renderCard(v));
    console.log(`wrote ${outDir}/${v.file}.svg`);
  }
}
