# Changelog

## 0.1.0 — 2026-10-03

First release: the checks from the AccessNow Spam Eater WordPress plugin as a framework-free PHP library.

- Honeypot, JavaScript token, signed timestamp and interaction checks, with the plugin's reference codes.
- Repeat-bot blocking (file storage, or your own `Storage`), Always allow and Always block lists (IPv4 and IPv6, CIDR).
- Your own words, phrases and regular expressions; about 9,000 throwaway email domains.
- `full`, `basic` and `login` check contexts; a token refresh endpoint for cached pages; CSP nonce support.
