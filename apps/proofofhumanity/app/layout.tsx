import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Proof of Humanity — one human, one soulbound credential",
  description:
    "Prove you are a unique human with a Self zero-knowledge passport proof, then mint a soulbound, anonymous Proof-of-Humanity NFT on any EVM chain.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
