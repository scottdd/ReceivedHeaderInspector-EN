# Received Header Inspector (EN)

English-first fork of the Thunderbird add-on **ReceivedHeaderInspector** by **Olivier Poujade (Olivier P.)**.
Original project: https://github.com/PoujadeOlivier/ReceivedHeaderInspector
(listed on addons.thunderbird.net under the MIT/X11 license). All credit for the original design and code goes to the original author.

## What changed in this fork
- English is the default UI language (WebExtension i18n, `default_locale: "en"`); the original French strings are kept in `_locales/fr`, so French-language Thunderbird still shows French.
- Code comments and documentation translated to English.
- New name and add-on ID (`receivedheaderinspector-en@dowlen.net`) so it can be installed alongside the original. Version 1.6.0.
- No functional changes.

## What it does
Received Header Inspector helps you detect spoofing and phishing attempts. It parses the message's `Received` headers and shows the transit servers used to deliver the email, so you can check the sender's legitimacy and spot inconsistencies.

It uses the public Google DNS API (`https://dns.google/resolve`) to check the sending server and the sender's email domain, e.g. resolving the domain's IP address and fetching SPF (TXT) records.

## Build
```
cd src && zip -r ../dist/receivedheaderinspector-en-1.6.0-tb.xpi . -x '.*'   # or: python3 -m zipfile -c ...
```

## Examples (from the original project)
![Example 01](Ressources/ExempleSpoofing01.jpg)
![Example 02](Ressources/ExempleSpoofing02.jpg)

## License
MIT. See [LICENSE](LICENSE).
