// Proxy types the server reports (proxy_type on a log, proxy on an IP rule)
// when Palisade runs with --proxy-db. "" means not listed, or no file.
const labels: Record<string, string> = {
  VPN: "VPN",
  TOR: "Tor exit",
  DCH: "Data centre",
  PUB: "Public proxy",
  WEB: "Web proxy",
  RES: "Residential proxy",
  SES: "Search engine",
  AIC: "AI crawler",
  CPN: "Privacy relay",
  EPN: "Enterprise network",
};

// The types the threat score counts (internal/security/threatscore/proxy.go).
const scored = new Set(["VPN", "TOR", "DCH", "PUB", "WEB", "RES"]);

export const proxyLabel = (type: string) => labels[type] ?? type;

export const proxyScored = (type: string) => scored.has(type);

// Tooltip text: what the listing means for the score.
export const proxyTitle = (type: string) =>
  proxyScored(type) ? "Listed in the proxy database; counts toward the threat score" : "Listed in the proxy database; not scored";
