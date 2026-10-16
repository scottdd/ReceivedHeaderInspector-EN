// Pure header-analysis logic (no browser APIs), so it can be unit-tested in node.
// Text is returned as message keys + substitutions; the popup localizes them.

export const MAX_SPF_LOOKUPS = 10;

// ---------- generic helpers ----------
export function unfold(s) {
    return String(s ?? "").replace(/\r?\n[ \t]+/g, " ").replace(/\s+/g, " ").trim();
}
export function getHeader(headers, name) {
    const v = headers?.[name.toLowerCase()];
    if (v == null) return [];
    return (Array.isArray(v) ? v : [v]).map(unfold);
}

// ---------- IP helpers ----------
export function isIPv4(s) {
    const m = String(s).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return !!m && m.slice(1).every(o => +o <= 255);
}
export function isIPv6(s) { return String(s).includes(":") && ipv6ToBig(s) !== null; }
export function isIP(s) { return isIPv4(s) || isIPv6(s); }

function ipv4ToBig(s) { return s.split(".").reduce((a, o) => (a << 8n) + BigInt(+o), 0n); }
function ipv6ToBig(s) {
    s = String(s).replace(/^\[|\]$/g, "").replace(/^IPv6:/i, "").split("%")[0];
    if (!/^[0-9a-f:.]+$/i.test(s)) return null;
    let tail = [];
    const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
    if (v4) {
        if (!isIPv4(v4[1])) return null;
        const n = ipv4ToBig(v4[1]);
        tail = [(n >> 16n).toString(16), (n & 0xffffn).toString(16)];
        s = s.slice(0, -v4[1].length) + "x";
    }
    const halves = s.split("::");
    if (halves.length > 2) return null;
    const parse = h => h === "" ? [] : h.split(":");
    let head = parse(halves[0]), rest = halves.length === 2 ? parse(halves[1]) : [];
    const fix = arr => arr.flatMap(g => g === "x" ? tail : [g]);
    head = fix(head); rest = fix(rest);
    let groups;
    if (halves.length === 2) {
        const fill = 8 - head.length - rest.length;
        if (fill < 1) return null;
        groups = [...head, ...Array(fill).fill("0"), ...rest];
    } else groups = head;
    if (groups.length !== 8 || !groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return null;
    return groups.reduce((a, g) => (a << 16n) + BigInt("0x" + g), 0n);
}
export function ipToBig(ip) {
    if (isIPv4(ip)) return { v: 4, n: ipv4ToBig(ip) };
    const n = ipv6ToBig(ip);
    if (n === null) return null;
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as the IPv4 address it wraps (RFC 7208 5, RFC 4291 2.5.5.2)
    if ((n >> 32n) === 0xffffn) return { v: 4, n: n & 0xffffffffn };
    return { v: 6, n };
}
// Text form used for display and DNS: bare address (no brackets / "IPv6:" tag); IPv4-mapped becomes dotted IPv4.
export function normalizeIP(ip) {
    const s = String(ip).replace(/^\[|\]$/g, "").replace(/^IPv6:/i, "").replace(/%[0-9a-z._~-]+$/i, "");
    const x = ipToBig(s);
    if (x && x.v === 4 && !isIPv4(s)) return [24n, 16n, 8n, 0n].map(sh => Number((x.n >> sh) & 255n)).join(".");
    return s;
}
export function sameIP(a, b) {
    const x = ipToBig(a), y = ipToBig(b);
    return !!x && !!y && x.v === y.v && x.n === y.n;
}
export function cidrMatch(ip, net, bits) {
    const x = ipToBig(ip), y = ipToBig(net);
    if (!x || !y || x.v !== y.v) return false;
    const width = x.v === 4 ? 32 : 128;
    if (bits == null) bits = width;
    if (bits < 0 || bits > width) return false;
    const shift = BigInt(width - bits);
    return (x.n >> shift) === (y.n >> shift);
}
export function isPublicIP(ip) {
    ip = normalizeIP(ip);
    if (isIPv4(ip)) {
        const priv = [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16], ["127.0.0.0", 8],
            ["169.254.0.0", 16], ["100.64.0.0", 10], ["0.0.0.0", 8], ["224.0.0.0", 4]];
        return !priv.some(([n, b]) => cidrMatch(ip, n, b));
    }
    if (isIPv6(ip)) {
        return !(sameIP(ip, "::1") || cidrMatch(ip, "fc00::", 7) || cidrMatch(ip, "fe80::", 10) || sameIP(ip, "::") || cidrMatch(ip, "ff00::", 8));
    }
    return false;
}
export function ptrName(ip) {
    if (isIPv4(ip)) return ip.split(".").reverse().join(".") + ".in-addr.arpa";
    const x = ipToBig(ip);
    return x.n.toString(16).padStart(32, "0").split("").reverse().join(".") + ".ip6.arpa";
}

// ---------- address / header parsing ----------
export function parseAddress(s) {
    s = unfold(s);
    let name = "", address = "";
    let m = s.match(/^(.*?)<\s*([^<>\s]*)\s*>/);
    if (m) { name = m[1].trim().replace(/^"(.*)"$/, "$1").trim(); address = m[2]; }
    else {
        m = s.match(/[^\s<>"(),;:]+@[^\s<>"(),;:]+/);
        if (m) address = m[0];
        name = (address ? s.replace(address, "") : s).replace(/[()"<>]/g, "").trim();
    }
    address = address.replace(/^mailto:/i, "");
    const domain = address.includes("@") ? address.split("@").pop().toLowerCase().replace(/\.$/, "") : "";
    return { name, address, domain };
}
export function parseTags(s) {
    const tags = {};
    for (const part of String(s).split(";")) {
        const i = part.indexOf("=");
        if (i < 0) continue;
        tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, "");
    }
    return tags;
}
export function parseDkimSignature(s) {
    const t = parseTags(unfold(s));
    return { d: (t.d || "").toLowerCase(), s: t.s || "" };
}

// Parse one Received header.
export function parseReceived(raw) {
    const s = unfold(raw);
    const semi = s.lastIndexOf(";");
    const body = semi >= 0 ? s.slice(0, semi) : s;
    const r = { raw: s, date: semi >= 0 ? s.slice(semi + 1).trim() : "", helo: "", rdns: "", ip: "", by: "", hasFrom: false };
    const byM = body.match(/\bby\s+([^\s();]+)/i);
    if (byM) r.by = byM[1].toLowerCase();
    const fromM = body.match(/^\s*from\s+(.*?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)/i);
    if (fromM) {
        r.hasFrom = true;
        const fp = fromM[1];
        let helo = (fp.match(/^(\S+)/) || ["", ""])[1];
        const ipM = fp.match(/\[(?:IPv6:)?([0-9a-f:.]+(?:%[0-9a-z._~-]+)?)\]/i);
        if (ipM && isIP(ipM[1])) r.ip = ipM[1];
        const par = fp.match(/\(([^)]*)\)/);
        if (par) {
            const inner = par[1].trim();
            const heloM = inner.match(/helo=([^\s)\]]+)/i);
            if (heloM) { // Exim style: from <rdns> ([ip] helo=<helo>)
                const tok = helo.replace(/^\[|\]$/g, "");
                r.rdns = isIP(tok) ? "" : helo;
                helo = heloM[1];
            } else {
                const first = inner.split(/\s+/)[0];
                const firstBare = first.replace(/^\[|\]$/g, "").replace(/^IPv6:/i, "").replace(/%[0-9a-z._~-]+$/i, "");
                if (first && !first.startsWith("[") && /[a-z]/i.test(first) && first.includes(".") && !isIP(firstBare)) r.rdns = first;
                else if (!r.ip && isIP(firstBare)) r.ip = firstBare; // Microsoft style: from host (ip)
            }
        }
        if (!r.ip && isIP(helo.replace(/^\[|\]$/g, "").replace(/%[0-9a-z._~-]+$/i, ""))) r.ip = helo.replace(/^\[|\]$/g, "");
        if (r.ip) r.ip = normalizeIP(r.ip);
        r.helo = helo.replace(/^\[(?:IPv6:)?|\]$/gi, "").toLowerCase();
        r.rdns = r.rdns.replace(/\.$/, "").toLowerCase();
    }
    return r;
}

// The handoff hop: the topmost Received with a "from" clause from a public IP
// (i.e. written by the user's own server when accepting the message from outside).
export function findHandoff(received) {
    let i = received.findIndex(r => r.hasFrom && r.ip && isPublicIP(r.ip));
    if (i < 0) i = received.findIndex(r => r.hasFrom);
    return i < 0 ? null : { index: i, hop: received[i] };
}

// ---------- Authentication-Results ----------
function splitTopLevel(s, sep) {
    const out = []; let depth = 0, cur = "", q = false;
    for (const ch of s) {
        if (ch === '"') q = !q;
        if (!q && ch === "(") depth++;
        if (!q && ch === ")") depth = Math.max(0, depth - 1);
        if (ch === sep && depth === 0 && !q) { out.push(cur); cur = ""; } else cur += ch;
    }
    out.push(cur);
    return out;
}
export function parseAuthResults(raw) {
    const s = unfold(raw);
    const parts = splitTopLevel(s, ";");
    // Exchange Online's internal stamps have no authserv-id ("spf=pass (sender IP is ...) smtp.mailfrom=...").
    const head = parts[0].replace(/\([^)]*\)/g, " ").trim();
    const noId = /^[a-z0-9_-]+\s*=\s*[a-z]+/i.test(head);
    const authserv = noId ? "" : (head.split(/\s+/)[0] || "").toLowerCase();
    const results = [];
    for (const p of (noId ? parts : parts.slice(1))) {
        const comments = [...p.matchAll(/\(([^)]*)\)/g)].map(m => m[1]);
        const clean = p.replace(/\([^)]*\)/g, " ").trim();
        const m = clean.match(/^([a-z0-9_-]+)\s*=\s*([a-z]+)/i);
        if (!m) continue;
        const props = {};
        for (const pm of clean.slice(m[0].length).matchAll(/([a-z0-9_-]+(?:\.[a-z0-9_-]+)?)\s*=\s*("[^"]*"|[^\s;]+)/gi))
            props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "");
        const cprops = {};
        for (const c of comments) for (const cm of c.matchAll(/\b([a-z]+)=([a-z0-9._-]+)/gi)) cprops[cm[1].toLowerCase()] = cm[2].toLowerCase();
        results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, cprops });
    }
    return { authserv, results, raw: s };
}
// Trust the topmost AR header, plus any whose authserv-id equals the topmost Received "by" host.
// Other AR headers are not used. Those that claim results and whose authserv-id does not share the
// organizational domain of the trusted authserv-id are "flagged" as possibly forged; same-org ones
// (internal multi-hop filtering) are just ignored.
export function selectAR(arList, topBy) {
    const byHosts = (Array.isArray(topBy) ? topBy : [topBy]).filter(Boolean).map(h => h.toLowerCase());
    const trusted = [], ignored = [], flagged = [];
    arList.forEach((a, i) => {
        if (i === 0 || byHosts.includes(a.authserv)) trusted.push(a); else ignored.push(a);
    });
    const trustedOrgs = new Set(trusted.map(a => orgDomain(a.authserv)));
    for (const a of ignored) {
        // No authserv-id (Exchange Online internal stamp): cannot be attributed to a host, so it is ignored but not flagged.
        if (a.authserv && a.results.length && !trusted.some(t => t.authserv === a.authserv) && !trustedOrgs.has(orgDomain(a.authserv))) flagged.push(a);
    }
    return { trusted, ignored: ignored.filter(a => !flagged.includes(a)), flagged };
}

// ---------- SPF ----------
const QUAL = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
async function getSpfRecord(domain, dns) {
    let txts;
    try { txts = await dns.txt(domain); } catch { return { error: "temperror" }; }
    const recs = txts.filter(t => /^v=spf1(\s|$)/i.test(t.trim()));
    if (!recs.length) return { record: null };
    if (recs.length > 1) return { error: "permerror" };
    return { record: recs[0].trim() };
}
async function addrsFor(name, v, dns) { return v === 4 ? dns.a(name) : dns.aaaa(name); }

// RFC 7208 check_host() subset: ip4, ip6, a, mx, include, exists, ptr (never matches), all, redirect=.
// Macros are not supported (yields neutral).
export async function checkSpf(ip, domain, dns, st = { lookups: 0 }, depth = 0) {
    const ipInfo = ipToBig(ip);
    if (!ipInfo || !domain) return { result: "none" };
    if (depth > 10) return { result: "permerror", reason: "recursion" };
    const rec = await getSpfRecord(domain, dns);
    if (rec.error) return { result: rec.error };
    if (!rec.record) return { result: "none" };
    const terms = rec.record.split(/\s+/).slice(1);
    let redirect = null;
    try {
        for (const term of terms) {
            const mod = term.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
            if (mod) { if (mod[1].toLowerCase() === "redirect") redirect = mod[2]; continue; }
            const m = term.match(/^([+\-~?]?)([a-z0-9]+)(?::([^/]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/i);
            if (!m) return { result: "permerror", reason: "bad term " + term };
            const q = m[1] || "+", mech = m[2].toLowerCase(), arg = m[3];
            const c4 = m[4] != null ? +m[4] : null, c6 = m[5] != null ? +m[5] : null;
            if (arg && arg.includes("%")) return { result: "neutral", reason: "macro not supported" };
            const bits = ipInfo.v === 4 ? (c4 ?? 32) : (c6 ?? 128);
            let match = false;
            switch (mech) {
                case "all": match = true; break;
                case "ip4": if (ipInfo.v === 4) match = cidrMatch(ip, arg, c4 ?? 32); break;
                case "ip6": if (ipInfo.v === 6) match = cidrMatch(ip, arg, c4 ?? 128); break;
                case "a": case "mx": case "include": case "exists": case "ptr": {
                    if (++st.lookups > MAX_SPF_LOOKUPS) return { result: "permerror", reason: "too many DNS lookups" };
                    const target = arg || domain;
                    if (mech === "a") match = (await addrsFor(target, ipInfo.v, dns)).some(a => cidrMatch(ip, a, bits));
                    else if (mech === "mx") {
                        const mxs = await dns.mx(target);
                        if (mxs.length > 10) return { result: "permerror", reason: "too many MX" };
                        for (const h of mxs) if ((await addrsFor(h, ipInfo.v, dns)).some(a => cidrMatch(ip, a, bits))) { match = true; break; }
                    } else if (mech === "exists") match = (await dns.a(target)).length > 0;
                    else if (mech === "include") {
                        if (!arg) return { result: "permerror", reason: "include without domain" };
                        const r = await checkSpf(ip, arg, dns, st, depth + 1);
                        if (r.result === "pass") match = true;
                        else if (r.result === "temperror") return r;
                        else if (r.result === "permerror" || r.result === "none") return { result: "permerror", reason: r.reason || "include " + arg + " has no SPF" };
                    }
                    // ptr: deprecated, treated as no match
                    break;
                }
                default: return { result: "permerror", reason: "unknown mechanism " + mech };
            }
            if (match) return { result: QUAL[q], mechanism: term, domain };
        }
        if (redirect) {
            if (++st.lookups > MAX_SPF_LOOKUPS) return { result: "permerror", reason: "too many DNS lookups" };
            const r = await checkSpf(ip, redirect, dns, st, depth + 1);
            if (r.result === "none") return { result: "permerror", reason: "redirect target has no SPF" };
            return r;
        }
    } catch (e) {
        return { result: "temperror", reason: String(e?.message || e) };
    }
    return { result: "neutral", reason: "no match", domain };
}

// ---------- DMARC ----------
const TWO_LEVEL = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp",
    "co.nz", "com.br", "co.in", "co.za", "com.cn", "com.mx", "com.tr", "co.kr", "com.sg", "com.ar"]);
// Approximate organizational domain: last two labels (three for a few well-known two-level suffixes).
export function orgDomain(d) {
    const l = String(d).toLowerCase().replace(/\.$/, "").split(".");
    if (l.length >= 3 && TWO_LEVEL.has(l.slice(-2).join("."))) return l.slice(-3).join(".");
    return l.slice(-2).join(".");
}
export function aligned(a, b, mode = "r") {
    if (!a || !b) return false;
    a = a.toLowerCase().replace(/\.$/, ""); b = b.toLowerCase().replace(/\.$/, "");
    return mode === "s" ? a === b : orgDomain(a) === orgDomain(b);
}
export async function fetchDmarc(domain, dns) {
    if (!domain) return null;
    const cands = [...new Set([domain, orgDomain(domain)])];
    for (const d of cands) {
        const txts = await dns.txt("_dmarc." + d);
        const rec = txts.find(t => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
        if (rec) {
            const tags = parseTags(rec);
            return { domain: d, tags, policy: (d === domain ? tags.p : (tags.sp || tags.p)) || "none" };
        }
    }
    return null;
}
// Local DMARC evaluation from SPF/DKIM results.
export function evalDmarc({ fromDomain, spf, dkim, dkimVerified, signatures, record }) {
    if (!record) return { result: "none" };
    const aspf = (record.tags.aspf || "r").toLowerCase(), adkim = (record.tags.adkim || "r").toLowerCase();
    const spfAligned = spf?.result === "pass" && aligned(spf.domain, fromDomain, aspf);
    const dkimAligned = (dkim || []).some(x => x.result === "pass" && aligned(x.d, fromDomain, adkim));
    if (spfAligned || dkimAligned) return { result: "pass", spfAligned, dkimAligned, policy: record.policy };
    if (!dkimVerified && (signatures || []).some(s => aligned(s.d, fromDomain, adkim)))
        return { result: "neutral", policy: record.policy, unverifiedDkim: true };
    return { result: "fail", policy: record.policy };
}

// ---------- reverse DNS ----------
export async function checkRdns(ip, helo, dns) {
    if (!ip) return { result: "neutral", key: "noHandoff", subs: [] };
    let names;
    try { names = await dns.ptr(ptrName(ip)); } catch { return { result: "temperror", key: "dnsError", subs: [] }; }
    if (!names.length) return { result: "fail", key: "rdnsNone", subs: [ip] };
    // Forward-confirm each PTR name (max 5) via A (IPv4 client) or AAAA (IPv6 client).
    const family = ipToBig(ip).v;
    const confirmed = [];
    for (const n of names.slice(0, 5).map(x => x.toLowerCase())) {
        try { if ((await addrsFor(n, family, dns)).some(a => sameIP(a, ip))) confirmed.push(n); }
        catch { return { result: "temperror", key: "dnsError", subs: [] }; }
    }
    if (!confirmed.length) return { result: "fail", key: "rdnsNotConfirmed", subs: [ip, names[0].toLowerCase()] };
    const h = (helo || "").toLowerCase();
    if (h && confirmed.includes(h)) return { result: "pass", key: "rdnsMatch", subs: [ip, h] };
    return { result: "neutral", key: "rdnsMismatch", subs: [ip, confirmed[0], helo || "?"] };
}

// ---------- claim ----------
export function extractClaim(headers) {
    const received = getHeader(headers, "received").map(parseReceived);
    const from = parseAddress(getHeader(headers, "from")[0] || "");
    const rpRaw = getHeader(headers, "return-path")[0];
    return {
        subject: getHeader(headers, "subject")[0] || "",
        from,
        returnPath: rpRaw != null ? parseAddress(rpRaw) : null,
        dkim: getHeader(headers, "dkim-signature").map(parseDkimSignature).filter(s => s.d),
        sender: getHeader(headers, "sender")[0] || getHeader(headers, "x-sender")[0] || "",
        received,
        handoff: findHandoff(received)
    };
}

// ---------- internal (same-tenant Microsoft 365) detection ----------
// Mail between two users of one Exchange Online tenant never leaves Microsoft's network, so SPF/DKIM/DMARC are not
// evaluated normally. It is declared "internal" only when ALL hold:
//  1. Exchange's stamp X-MS-Exchange-Organization-AuthAs (or x-ms-exchange-crosstenant-authas) is "Internal";
//  2. every Received hop is a Microsoft hop (Microsoft host names; "from" addresses only ::1, fe80::/10, 2603:10b6::/32,
//     2a01:111::/32 or absent) so no outside server touched the message;
//  3. every Authentication-Results header comes from Microsoft (e.g. mx.microsoft.com) or has no authserv-id.
// The stamp is added in the SENDER's tenant and stays on the message when it is relayed to outside recipients, so on a
// path that includes any non-Microsoft hop it is simply ignored (no warning, no verdict change): the message is analyzed
// like any other mail, and a forged stamp gains an outsider nothing. Only the all-Microsoft path with a foreign
// Authentication-Results header is treated as a possible forgery (analyzed normally, capped at "Suspicious", warning row).
export function isMicrosoftHost(h) {
    return /(^|\.)(outlook\.com|office365\.com|office\.com|microsoft\.com)$/i.test(String(h || "").replace(/\.$/, ""));
}
function isMicrosoftInternalIP(ip) {
    if (!ip) return true;
    return sameIP(ip, "::1") || cidrMatch(ip, "fe80::", 10) || cidrMatch(ip, "2603:10b6::", 32) || cidrMatch(ip, "2a01:111::", 32);
}
export function isMicrosoftHop(r) {
    if (!r.by || !isMicrosoftHost(r.by)) return false;
    if (!r.hasFrom) return true;
    return (r.helo ? isMicrosoftHost(r.helo) : true) && isMicrosoftInternalIP(r.ip);
}
export function internalStamp(headers) {
    return ["x-ms-exchange-organization-authas", "x-ms-exchange-crosstenant-authas"]
        .some(n => getHeader(headers, n).some(v => /^internal$/i.test(v.trim())));
}
// -> { state: "none" | "internal" | "forged", authserv?: string }   ("forged" = all-Microsoft path but foreign Authentication-Results)
export function detectInternal(headers) {
    if (!internalStamp(headers)) return { state: "none" };
    const received = getHeader(headers, "received").map(parseReceived);
    if (!received.length || !received.every(isMicrosoftHop)) return { state: "none" };
    const foreign = getHeader(headers, "authentication-results").map(parseAuthResults).find(a => a.authserv && !isMicrosoftHost(a.authserv));
    if (foreign) return { state: "forged", authserv: foreign.authserv };
    return { state: "internal" };
}

// ---------- verdict ----------
export function verdict(fromDomain, c) {
    if (c.internal) return { level: "internal", key: "reasonInternal", subs: [fromDomain] };
    const v = baseVerdict(fromDomain, c);
    if (c.internalStampWarning) {
        if (v.level === "authentic") return { level: "suspicious", key: "reasonDockedInternalStamp", subs: [fromDomain], docked: true };
        if (v.level === "suspicious") return { ...v, key: "reasonMixedInternalStamp" };
    }
    if (c.arFlagged?.length) {
        if (v.level === "authentic") return { level: "suspicious", key: "reasonDockedAR", subs: [fromDomain], docked: true };
        if (v.level === "suspicious") return { ...v, key: "reasonMixedAR" };
    }
    return v;
}
function baseVerdict(fromDomain, c) {
    if (c.dmarc.result === "pass") return { level: "authentic", key: "reasonDmarcPass", subs: [fromDomain] };
    if (c.dmarc.result === "fail") return { level: "spoofed", key: "reasonDmarcFail", subs: [fromDomain] };
    const dkimAlignedPass = c.dkim.items.some(x => x.result === "pass" && aligned(x.d, fromDomain));
    if (dkimAlignedPass) return { level: "authentic", key: "reasonAlignedDkim", subs: [fromDomain] };
    if (c.spf.result === "pass" && aligned(c.spf.domain, fromDomain)) return { level: "authentic", key: "reasonAlignedSpf", subs: [fromDomain] };
    if (c.spf.result === "fail") {
        // An aligned DKIM signature we could not verify locally is not evidence of forgery: stay "suspicious".
        if (c.dkimUnverifiedAligned) return { level: "suspicious", key: "reasonSpfFailDkimUnverified", subs: [fromDomain] };
        return { level: "spoofed", key: "reasonSpfFail", subs: [fromDomain] };
    }
    return { level: "suspicious", key: "reasonMixed", subs: [fromDomain] };
}

// ---------- full analysis ----------
export async function analyze(headers, dns) {
    const claim = extractClaim(headers);
    const fromDomain = claim.from.domain;
    const internal = detectInternal(headers);
    if (internal.state === "internal") {
        const na = { result: "na", items: [], source: { type: "none" } };
        const confirm = { internal: true, spf: { ...na }, dkim: { ...na }, dmarc: { ...na }, rdns: { ...na }, arIgnored: 0, arFlagged: [] };
        return { claim, confirm, internal, verdict: verdict(fromDomain, confirm) };
    }
    const hop = claim.handoff?.hop || null;
    // Own-server host names: "by" of every hop from the top down to (and including) the handoff hop.
    const upTo = claim.handoff ? claim.handoff.index : 0;
    const ownBy = claim.received.slice(0, upTo + 1).map(r => r.by).filter(Boolean);
    const ar = selectAR(getHeader(headers, "authentication-results").map(parseAuthResults), ownBy);
    const all = ar.trusted.flatMap(a => a.results.map(r => ({ ...r, by: a.authserv })));
    const own = () => { const sc = dns.scope ? dns.scope() : dns; return { dns: sc, source: { type: "own", get resolvers() { return [...(sc.used || [])]; } } }; };
    const envDomain = claim.returnPath?.domain || "";

    // SPF
    let spf;
    const arSpf = all.find(r => r.method === "spf");
    if (arSpf) {
        const mf = arSpf.props["smtp.mailfrom"] || "";
        const d = mf.includes("@") ? mf.split("@").pop() : (mf || envDomain || arSpf.props["smtp.helo"] || "");
        spf = { result: arSpf.result, domain: d.toLowerCase(), ip: hop?.ip || "", source: { type: "ar", by: arSpf.by } };
    } else {
        const d = envDomain || hop?.helo || "", o = own();
        const r = hop?.ip ? await checkSpf(hop.ip, d, o.dns) : { result: "none" };
        spf = { result: r.result, domain: d, ip: hop?.ip || "", reason: r.reason, mechanism: r.mechanism, source: o.source };
    }

    // DKIM
    let dkim;
    const arDkim = all.filter(r => r.method === "dkim");
    if (arDkim.length) {
        const items = arDkim.map(r => ({ result: r.result, d: (r.props["header.d"] || (r.props["header.i"] || "").split("@").pop() || "").toLowerCase() }));
        const res = items.some(i => i.result === "pass") ? "pass" : items[0].result;
        dkim = { result: res, items, verified: true, source: { type: "ar", by: arDkim[0].by } };
    } else {
        dkim = { result: claim.dkim.length ? "neutral" : "none", items: [], verified: false, notVerified: claim.dkim.length > 0, source: { type: "own", resolvers: [] } };
    }

    // DMARC
    let dmarc;
    const arDmarc = all.find(r => r.method === "dmarc");
    if (arDmarc) {
        const policy = arDmarc.props["policy.published-domain-policy"] || arDmarc.props["policy.dmarc"] || arDmarc.cprops.p || "";
        dmarc = { result: arDmarc.result, policy: policy.toLowerCase(), domain: (arDmarc.props["header.from"] || fromDomain).toLowerCase(), source: { type: "ar", by: arDmarc.by } };
    } else {
        let record = null, err = false; const o = own();
        try { record = await fetchDmarc(fromDomain, o.dns); } catch { err = true; }
        const r = err ? { result: "temperror" } : evalDmarc({ fromDomain, spf, dkim: dkim.items, dkimVerified: dkim.verified, signatures: claim.dkim, record });
        dmarc = { ...r, domain: fromDomain, policy: r.policy || "", orgNote: true, source: o.source };
    }

    const ro = own();
    const rdns = { ...(await checkRdns(hop?.ip, hop?.helo, ro.dns)), source: ro.source };
    const dkimUnverifiedAligned = !dkim.verified && claim.dkim.some(x => aligned(x.d, fromDomain));
    const confirm = { spf, dkim, dmarc, rdns, dkimUnverifiedAligned, arIgnored: ar.ignored.length, arFlagged: ar.flagged,
        arTrustedBy: ar.trusted[0]?.authserv || "",
        internalStampWarning: internal.state === "forged" ? { authserv: internal.authserv || "" } : null };
    return { claim, confirm, internal, verdict: verdict(fromDomain, confirm) };
}
