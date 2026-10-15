### Version 1.6.1 (English fork)
- Redesigned popup: Claim (From, Return-Path, DKIM d=, handoff server, Sender), Confirm (SPF, DKIM, DMARC, reverse DNS with pass/fail badges and source), Verdict, collapsible delivery path.
- Uses trusted Authentication-Results when present; otherwise own DNS-over-HTTPS checks (SPF evaluation, DMARC alignment). Reverse DNS is always checked locally.
- IPv6 support in Received parsing. Removed raw SPF/TXT record dump. Resolver URL configurable in dns.js (Google or Cloudflare).

### Version 1.6.0 (English fork)
- English-first fork: UI localized via WebExtension i18n (English default, French kept); comments translated; new name and ID. No functional changes.

### Version 1.5
- manifest.json fix.

### Version 1.4
- Uses the dns.google API. This version adds checks of the sending server and of the sender's email domain via Google's public DNS API, enabling security checks on that address (e.g. checking SPF records or getting the IP associated with a sending domain).

### Version 1.3
- Renamed for clarity.

### Version 1.2
- **Code optimization**: simplified and refactored `popup.js` for readability and maintainability, with no change in behavior or features.

### Version 1.1
- First stable version of **SendInspecteur**: displays transit servers and checks sender domains.
- Helps detect inconsistencies and prevent phishing and spoofing.

## Received Header Inspector
An extension designed to help users detect spoofing and phishing in their email. It displays the transit servers associated with received messages, so you can verify senders' legitimacy and spot inconsistencies in sender information.

### Main features
- **Transit server display**: see the sending servers of received emails.
- **Sender domain check**: compare the email address domain with the transit servers to detect inconsistencies.
- **Phishing protection**: use this information to spot suspicious messages and avoid spoofing scams.

### How does it work?
Open an email and click the add-on's button in the message toolbar; it analyzes the message headers to extract transit server information and displays it so you can check consistency with the sender's domain.

### Original author
Olivier Poujade (Olivier P.) - https://github.com/PoujadeOlivier/ReceivedHeaderInspector
