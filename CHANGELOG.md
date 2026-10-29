# Changelog

## 0.2.0 — 2026-10-29

- **Visitors get their own interaction token** when the site has a `refresh_url`. The script asks for it with a POST when the
  visitor first touches the page, so it is never in the page: before, the token was the same for every visitor and a bot that
  read the page once could reuse it (a sign-up bot did exactly that in October 2026). A token belongs to its form's timestamp.
- **New check, SE-R4:** one interaction token passes `token_uses` submissions (default 5).
- **New option `act_per_hour`** (default 60): how many interaction tokens one address can fetch an hour.
- A form sent in the same moment as the first touch is held until the visitor's token arrives (at most 4 seconds), then sent again.
- `sendTokens()` takes `$post` and `$server` for tests; `issueAct()` is public. Without a `refresh_url`, nothing changes.

## 0.1.0 — 2026-10-03

First release: the checks from the AccessNow Spam Eater WordPress plugin as a framework-free PHP library.

- Honeypot, JavaScript token, signed timestamp and interaction checks, with the plugin's reference codes.
- Repeat-bot blocking (file storage, or your own `Storage`), Always allow and Always block lists (IPv4 and IPv6, CIDR).
- Your own words, phrases and regular expressions; about 9,000 throwaway email domains.
- `full`, `basic` and `login` check contexts; a token refresh endpoint for cached pages; CSP nonce support.
