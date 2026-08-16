import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "UBI — verified by AI · streaming at 1/hour",
  description: "A UBI blockchain where humans are verified by AI and money flows as a stream.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Keep production builds network-independent. The complete system sans/mono
  // fallback stacks are declared in globals.css.
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
