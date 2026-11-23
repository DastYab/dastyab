# DastYab Censorship-Resistant Config Gatherer Roadmap

This roadmap prioritizes making DastYab the most complete, self-healing config gatherer for heavily restricted networks (Iran / National Information Network).

## Shipped Foundation (v0.1.x – v0.3.x)

- Resilient 5-level connectivity ladder (`direct` → `DoH` → `DoT` → `DNS-ARQ` → `LAN Mesh Relay`), daemon auto-refill, stealth anti-bot pacing, CT-log & authoritative NS out-of-band anchors, loopback subscription server, multi-hop chains, and Android Blackout Rescue hub.

---

## Prioritized Config Gatherer Roadmap (20 Concrete Enhancements)

### Sources
1. **[Phase 1 · Done] Unified 4-Type Source Store & Manager** — Manage GitHub raw files, arbitrary subscription URLs, Telegram public channels (`t.me/s/<ch>`), and Telegram single posts (`t.me/<ch>/<id>`) in one store with per-source telemetry (`lastFetchTime`, `configsFound`, `successRate`), bulk paste, JSON/text import-export, and reset-to-defaults across Android & `dastyab-cli`.
2. **[Phase 1 · Done] Expanded Public Aggregators & Multi-Page Telegram Scraping** — Curated default lists covering major public GitHub config collectors (`barry-far`, `Epodonios`, `MahsaNetConfigTopic`, `yebekhe`, `NiREvil`, `soroushmirzaei`, `MrMohebi`, `SoliSpirit`, `peasoft`, `0xRadikal`, `liMilCo`) and Persian Telegram channels scraped across multiple `?before=<id>` history pages plus single-post embed fetches.
3. **[Phase 2] Autonomous Telegram Graph & Repo Topic Crawler** — Automatically score yielded channels/repos, promote newly discovered high-yield sources into the active pool, and prune chronically dead endpoints after cooldown.
4. **[Phase 2] Alternate Drop Channels (Pastebin, Telegraph, Gist, Cloudflare Worker Sub APIs)** — Support `telegra.ph`, `pastebin.com/raw`, `rentry.co`, `dpaste`, GitLab snippets, and Workers `.workers.dev` JSON/subscription feeds for out-of-band text drops when GitHub and Telegram are both filtered.
5. **[Phase 3] Domestic Mirror & IPFS/ENS Feed Discovery** — Resolve signed config catalogs stored in IPFS gateways, DoH TXT records, or Iranian-accessible CDN mirrors without hardcoded central domains.

### Protocols
6. **[Phase 1 · Done] Complete Share-Link Normalization & Dedup (`protocol+host+port+id`)** — Unified Kotlin + Rust parser covering `vless`, `vmess`, `trojan`, `ss`, `ssr`, `hysteria`, `hysteria2`/`hy2`, `tuic`, `wireguard`/`wg`, `socks`/`socks5`, `http`, `https`, `naive+https`, `juicity`, and `anytls`, deduplicating identically on canonical scheme + host + port + credential/id.
7. **[Phase 1 · Done] Nested Sing-Box JSON, Clash/Mihomo YAML & Multi-Layer Base64 Decoder** — Brace-balanced JSON extractor for full Sing-Box `outbounds` (TLS, SNI, transport, Reality keys) and Xray `vnext`, alongside full Clash/Mihomo YAML flow & block parsers and up to 3-layer recursive Base64 decoding.
8. **[Phase 2] WireGuard / AmneziaWG / WARP Parameter Synthesis & Magic Junk Preservation** — Parse and preserve AmneziaWG `Jc`/`Jmin`/`Jmax`/`S1`/`S2`/`H1..H4` obfuscation parameters and Cloudflare WARP `reserved` bytes across URI, INI, and Sing-Box export.
9. **[Phase 2] Reality / uTLS / gRPC / xHTTP (SplitHTTP) Full Fidelity Converter** — Bidirectional conversion between share-links, Xray JSON, and Sing-Box JSON for `xhttp`, `httpupgrade`, `grpc`, `ws` early-data, Reality (`pbk`/`sid`/`spx`), and uTLS fingerprints.
10. **[Phase 3] Multi-Hop Relay URI Synthesizer** — Pair harvested cheap domestic/relay SOCKS5/HTTP/WARP entry hops with censorship-resistant exit nodes (`dialer_proxy` / `detour`) to build ready-to-import chained configurations.

### Testing
11. **[Phase 1 · Done] Protocol-Aware TCP + TLS/SNI Latency Ranker** — Concurrent probe pipeline running TCP reachability + real TLS/SNI handshake verification (for TLS-backed protocols like VLESS-TLS/Trojan/Hy2/TUIC/Naive/AnyTLS/HTTPS), ranking reachable configs fastest-first and dropping dead/blackholed nodes.
12. **[Phase 2] End-to-End Real Egress 204 Verification on Android** — Spin up transient local SOCKS5 probes via embedded `libxray`/Sing-box core to verify HTTP 204 connectivity (`cp.cloudflare.com/generate_204`) and reject silent-TLS DPI blackholes.
13. **[Phase 2] Clean Cloudflare IP Auto-Repacking for WS/gRPC Harvested Nodes** — Automatically substitute slow/blocked edge IPs inside harvested Cloudflare-backed VLESS/VMess/Trojan configs with locally scouted clean edge IPs while preserving `sni` and `Host`.
14. **[Phase 3] Exit GeoIP & Service-Unlock Tagging (AI Studio / Flow / ChatGPT)** — Tag verified reachable configs with exit country flag, ASN risk class (residential/cloud/WARP), and Google AI Studio / Flow clearance before exporting.

### UX
15. **[Phase 1 · Done] Dedicated Android Source Manager & One-Tap External Client Export** — Filterable source screen (by source type & target protocol), bulk paste, JSON/text import-export, live harvest + latency test view, and one-tap export via Clipboard, Base64 subscription text, offline QR code, or direct handoff to **v2rayNG**, **Hiddify**, and **NekoBox**.
16. **[Phase 1 · Done] Matching CLI Source & Harvest Workflow (`dastyab-cli`)** — Full `dastyab sources {list|add|remove|enable|disable|import|export|ingest|refresh}` and `dastyab harvest --protocol <p> --test` commands mirroring Android source management and latency filtering.
17. **[Phase 2] On-Device Loopback Subscription Server on Android** — Serve the filtered, latency-tested reachable pool at `http://127.0.0.1:10852/subscription` from Android's background service so v2rayNG/Hiddify/NekoBox can auto-update offline without Telegram access.
18. **[Phase 3] Smart Config Renamer & Bilingual Subscription Diff Alerts** — Automatically label harvested nodes with latency, transport, protocol, and region tags in English/Persian, and surface digest summaries of newly discovered working servers.

### Resilience
19. **[Phase 1 · Done] Multi-CDN Mirror Fallback (`raw` → `jsDelivr` → `Statically`)** — Transparently cycle across `raw.githubusercontent.com`, `cdn.jsdelivr.net/gh/...`, and `cdn.statically.io/gh/...` whenever GitHub raw hosts are throttled or SNI-filtered, both in Android and `dastyab-core`.
20. **[Phase 2] Proxy-Routed Harvesting Through Active Local Tunnel** — Automatically route Android `HttpURLConnection` source fetches through an active local SOCKS5/HTTP bridge (`127.0.0.1:10850` / `10808` / Orbot) or Emergency DoH resolver when direct carrier paths block Telegram and GitHub mirrors.
21. **[Phase 3] Offline Blackout Bundle Gossip (QR / Nearby / File Vault)** — Signed delta packs of top-ranked working configs and verified sources that can cross air-gaps over Telegram exports, Bluetooth/Nearby Share, or multi-part QR codes during prolonged national shutdowns.
