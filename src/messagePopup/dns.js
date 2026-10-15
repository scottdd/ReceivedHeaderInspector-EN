// DNS over HTTPS (JSON API: ?name=&type=, application/dns-json) client with ordered fallback.
// Resolvers are tried in order; the next one is used on network error, timeout, HTTP error,
// unparsable reply, SERVFAIL or REFUSED. NXDOMAIN (Status 3) is a valid answer (no fallback).
// Keep manifest.json host permissions in sync with this list.
export const RESOLVERS = [
    { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
    { name: "NextDNS", url: "https://dns.nextdns.io/dns-query" },
    { name: "AdGuard", url: "https://unfiltered.adguard-dns.com/resolve" },
    { name: "DNS.SB", url: "https://doh.dns.sb/dns-query" },
    { name: "Google", url: "https://dns.google/resolve" }
];
export const TIMEOUT_MS = 3000;

const TYPES = { A: 1, AAAA: 28, MX: 15, TXT: 16, PTR: 12, CNAME: 5 };

// Join the quoted character-strings of a TXT record ("a" "b" -> ab); unquoted data is returned as is.
export function joinTxt(data) {
    const segs = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1].replace(/\\(.)/g, "$1"));
    return segs.length ? segs.join("") : String(data);
}

async function fetchWithTimeout(fetchFn, url, opts, ms) {
    const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    let timer;
    const timeout = new Promise((_, rej) => { timer = setTimeout(() => { ctl?.abort(); rej(new Error("timeout")); }, ms); });
    try {
        return await Promise.race([fetchFn(url, { ...opts, signal: ctl?.signal }), timeout]);
    } finally { clearTimeout(timer); }
}

export function createDns(fetchFn = (...a) => fetch(...a), resolvers = RESOLVERS, timeoutMs = TIMEOUT_MS) {
    const cache = new Map();
    async function resolve(name, type) {
        const errors = [];
        for (const r of resolvers) {
            try {
                const url = `${r.url}?name=${encodeURIComponent(name)}&type=${type}`;
                const res = await fetchWithTimeout(fetchFn, url, { headers: { accept: "application/dns-json" } }, timeoutMs);
                if (!res.ok) throw new Error("HTTP " + res.status);
                const d = await res.json();
                if (d.Status === 3) return { answers: [], resolver: r.name };
                if (d.Status !== 0) throw new Error("DNS status " + d.Status);
                return { answers: (d.Answer || []).filter(a => a.type === TYPES[type]).map(a => a.data), resolver: r.name };
            } catch (e) { errors.push(`${r.name}: ${e?.message || e}`); }
        }
        throw new Error("All resolvers failed (" + errors.join("; ") + ")");
    }
    function query(name, type) {
        name = String(name).replace(/\.$/, "");
        const key = type + " " + name.toLowerCase();
        if (!cache.has(key)) {
            const p = resolve(name, type);
            p.catch(() => cache.delete(key));
            cache.set(key, p);
        }
        return cache.get(key);
    }
    // A client that records which resolvers answered its queries (client.used).
    function scope() {
        const used = new Set();
        const q = async (n, t) => { const r = await query(n, t); used.add(r.resolver); return r.answers; };
        return {
            used,
            txt: async n => (await q(n, "TXT")).map(joinTxt),
            a: n => q(n, "A"),
            aaaa: n => q(n, "AAAA"),
            mx: async n => (await q(n, "MX")).map(d => d.trim().split(/\s+/).pop().replace(/\.$/, "")),
            ptr: async n => (await q(n, "PTR")).map(d => d.replace(/\.$/, "")),
            scope
        };
    }
    return scope();
}
