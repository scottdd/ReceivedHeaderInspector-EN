// DNS over HTTPS (JSON API) client.
// Change RESOLVER to swap the resolver; both Google and Cloudflare JSON APIs are supported.
export const RESOLVERS = {
    google: { url: "https://dns.google/resolve", style: "google" },
    cloudflare: { url: "https://cloudflare-dns.com/dns-query", style: "cloudflare" }
};
export const RESOLVER = RESOLVERS.google;

const TYPES = { A: 1, AAAA: 28, MX: 15, TXT: 16, PTR: 12, CNAME: 5 };

// Join the quoted character-strings of a TXT record ("a" "b" -> ab); unquoted data is returned as is.
export function joinTxt(data) {
    const segs = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1].replace(/\\(.)/g, "$1"));
    return segs.length ? segs.join("") : String(data);
}

export function createDns(fetchFn = (...a) => fetch(...a), resolver = RESOLVER) {
    const cache = new Map();
    async function query(name, type) {
        name = String(name).replace(/\.$/, "");
        const key = type + " " + name.toLowerCase();
        if (!cache.has(key)) {
            cache.set(key, (async () => {
                const url = `${resolver.url}?name=${encodeURIComponent(name)}&type=${type}`;
                const opts = resolver.style === "cloudflare" ? { headers: { accept: "application/dns-json" } } : {};
                const res = await fetchFn(url, opts);
                if (!res.ok) throw new Error("DNS HTTP " + res.status);
                const d = await res.json();
                if (d.Status === 3) return []; // NXDOMAIN
                if (d.Status !== 0) throw new Error("DNS status " + d.Status);
                return (d.Answer || []).filter(a => a.type === TYPES[type]).map(a => a.data);
            })());
        }
        return cache.get(key);
    }
    return {
        txt: async n => (await query(n, "TXT")).map(joinTxt),
        a: n => query(n, "A"),
        aaaa: n => query(n, "AAAA"),
        mx: async n => (await query(n, "MX")).map(d => d.trim().split(/\s+/).pop().replace(/\.$/, "")),
        ptr: async n => (await query(n, "PTR")).map(d => d.replace(/\.$/, ""))
    };
}
