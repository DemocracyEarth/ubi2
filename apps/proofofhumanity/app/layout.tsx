import type { Metadata, Viewport } from "next";
import "./globals.css";

const TITLE = "Proof of Humanity — one human, one credential";
const DESCRIPTION =
  "Prove you are a unique human with a Self zero-knowledge passport proof, then mint a minimal soulbound credential. Nothing personal on-chain — the predicates travel, not the data.";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://proofofhumanity.org";

// `app/icon.svg` and `app/apple-icon.png` are auto-wired by Next's file conventions,
// so favicons need no explicit config here. `metadataBase` makes the relative `/og.png`
// resolve to an absolute URL for Open Graph / Twitter crawlers.
export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: TITLE,
  description: DESCRIPTION,
  applicationName: "Proof of Humanity",
  keywords: [
    "proof of humanity",
    "zero-knowledge",
    "Self passport",
    "soulbound",
    "Sybil resistance",
    "UBI",
    "ERC-5192",
  ],
  authors: [{ name: "Democracy Earth" }],
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Proof of Humanity",
    title: TITLE,
    description: DESCRIPTION,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: TITLE }],
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
    images: ["/og.png"],
  },
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: "#050507",
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
