import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "UBI — wallet & explorer",
  description: "A UBI blockchain where humans are verified by AI and money flows as a stream.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
