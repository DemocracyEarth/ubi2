import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    id: "/",
    name: "Proof of Humanity",
    short_name: "PoH",
    description: "Self passport proof, soulbound humanity mint, and private predicates on Base Sepolia.",
    start_url: "/#mint",
    scope: "/",
    display: "standalone",
    background_color: "#050507",
    theme_color: "#050507",
    categories: ["finance", "security", "utilities"],
    icons: [
      { src: "/icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
      { src: "/apple-icon.png", sizes: "180x180", type: "image/png", purpose: "any" },
    ],
  };
}
