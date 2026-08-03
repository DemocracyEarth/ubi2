/**
 * Render an UNTRUSTED on-chain SVG string as an inert `<img>` data-URI source (issue #38 / FU-17).
 *
 * The card SVG is decoded from an NFT `tokenURI` fetched via `eth_call`. Under the wallet's stated
 * "trust no server — the RPC/gateway is untrusted" threat model, a malicious or compromised node could
 * return SVG carrying `<script>` or event-handler attributes (`<img onerror=…>`, `<svg onload=…>`).
 * Injecting that with `dangerouslySetInnerHTML` runs it as live DOM, so those handlers execute — XSS.
 *
 * An `<img src={svgImageSrc(svg)} />` instead renders the SVG in an IMAGE context: the browser executes
 * no scripts and fires no event handlers from image content, so a hostile SVG can at worst draw garbage,
 * never run code. This needs no sanitizer dependency and closes the vector at the source.
 */
export function svgImageSrc(svg: string): string {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
}
