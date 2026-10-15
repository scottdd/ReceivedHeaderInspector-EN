# TODO

- [ ] Options page: trusted mail server name, resolver list/order, round-robin vs fallback mode
- [ ] Binary DoH (RFC 8484, `application/dns-message`) support, e.g. for Quad9 and Mullvad (no JSON API)
- [ ] LAN / local resolver support
- [ ] DKIM cryptographic verification in the fallback path (WebCrypto)
- [ ] Full Public Suffix List for organizational-domain / alignment checks
- [ ] SPF macros and the void-lookup limit
- [ ] Languages: add translations for the 10 most widely spoken languages first (English, Mandarin Chinese, Hindi, Spanish, French, Arabic (incl. RTL layout), Bengali, Portuguese, Russian, Urdu), then expand. Add a language selector to the options page once it is built (default: follow the Thunderbird UI language).
  - Source check (2026-10-14): this list matches the CIA World Factbook 2022 top 10 (English, Mandarin, Hindi, Spanish, French, Arabic, Bengali, Russian, Portuguese, Urdu). Ethnologue 2026 total speakers (L1+L2; Wikipedia "List of languages by total number of speakers"), which splits out Arabic varieties, ranks: English, Mandarin, Hindi, Spanish, Modern Standard Arabic, French, Bengali, Portuguese, **Indonesian**, Urdu, then Russian (11th). So by Ethnologue Indonesian would replace Russian in the top 10; decide whether to add Indonesian too. Arabic and Urdu need RTL layout.
