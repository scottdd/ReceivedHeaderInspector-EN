import assert from "node:assert/strict";
import * as L from "../src/messagePopup/lib.js";
import { joinTxt, createDns } from "../src/messagePopup/dns.js";
import { authenticHeaders, forgedARHeaders, spoofHeaders, mockDns, zone } from "./fixtures.js";

let pass = 0, fail = 0;
async function test(name, fn) {
    try { await fn(); pass++; console.log("  ok  " + name); }
    catch (e) { fail++; console.log("  FAIL " + name + "\n       " + e.message); }
}

await test("parseAddress with display name", () => {
    assert.deepEqual(L.parseAddress('"Example Billing" <Billing@Example.com>'), { name: "Example Billing", address: "Billing@Example.com", domain: "example.com" });
    assert.equal(L.parseAddress("<>").address, "");
    assert.equal(L.parseAddress("plain@x.example").domain, "x.example");
});
await test("parseReceived postfix", () => {
    const r = L.parseReceived(authenticHeaders.received[0]);
    assert.equal(r.helo, "out-3.mail.example.com"); assert.equal(r.rdns, "out-3.mail.example.com");
    assert.equal(r.ip, "203.0.113.25"); assert.equal(r.by, "mx.home.example.net");
    assert.match(r.date, /^Wed, 14 Oct 2026 18:02:11/);
});
await test("parseReceived postfix unknown rdns", () => {
    const r = L.parseReceived(spoofHeaders.received[1]);
    assert.equal(r.helo, "mailer.example.org"); assert.equal(r.rdns, ""); assert.equal(r.ip, "198.51.100.77");
});
await test("parseReceived exim with helo=", () => {
    const r = L.parseReceived("from smtp.rdns.example ([203.0.113.7] helo=claimed.example) by mx.example with esmtps; Mon, 1 Jan 2026 00:00:00 +0000");
    assert.equal(r.helo, "claimed.example"); assert.equal(r.rdns, "smtp.rdns.example"); assert.equal(r.ip, "203.0.113.7");
});
await test("parseReceived IPv6 in brackets", () => {
    const r = L.parseReceived("from mail.example.com (mail.example.com [IPv6:2001:db8::25]) by mx.example.net; Mon, 1 Jan 2026 00:00:00 +0000");
    assert.equal(r.ip, "2001:db8::25");
});
await test("parseReceived Microsoft style ip in parens", () => {
    const r = L.parseReceived("from EX1.contoso.example (2001:db8:1::5) by EX2.contoso.example (2001:db8:1::6) with Microsoft SMTP Server; Mon, 1 Jan 2026");
    assert.equal(r.ip, "2001:db8:1::5"); assert.equal(r.by, "ex2.contoso.example");
});
await test("findHandoff skips loopback hop", () => {
    const h = L.findHandoff(spoofHeaders.received.map(L.parseReceived));
    assert.equal(h.index, 1); assert.equal(h.hop.ip, "198.51.100.77");
});
await test("DKIM-Signature d= and s=", () => {
    assert.deepEqual(L.parseDkimSignature(authenticHeaders["dkim-signature"][0]), { d: "example.com", s: "s1" });
});
await test("parseAuthResults", () => {
    const a = L.parseAuthResults(authenticHeaders["authentication-results"][0]);
    assert.equal(a.authserv, "mx.home.example.net");
    assert.deepEqual(a.results.map(r => r.method + "=" + r.result), ["spf=pass", "dkim=pass", "dmarc=pass"]);
    assert.equal(a.results[0].props["smtp.mailfrom"], "bounce-8812@mail.example.com");
    assert.equal(a.results[2].cprops.p, "reject");
});
await test("selectAR trusts topmost / matching authserv only", () => {
    const list = authenticHeaders["authentication-results"].map(L.parseAuthResults);
    const s = L.selectAR(list, "mx.home.example.net");
    assert.equal(s.trusted.length, 1); assert.equal(s.flagged.length, 1); assert.equal(s.flagged[0].authserv, "evil.example.org");
    const s2 = L.selectAR([list[1], list[0]], "mx.home.example.net");
    assert.equal(s2.trusted.length, 2);
});
await test("CIDR v4/v6, ptrName", () => {
    assert.ok(L.cidrMatch("203.0.113.25", "203.0.113.0", 26));
    assert.ok(!L.cidrMatch("203.0.113.70", "203.0.113.0", 26));
    assert.ok(L.cidrMatch("2001:db8:10::1", "2001:db8:10::", 48));
    assert.ok(!L.cidrMatch("2001:db8:11::1", "2001:db8:10::", 48));
    assert.ok(L.sameIP("::ffff:192.0.2.1", "0:0:0:0:0:ffff:c000:201"));
    assert.equal(L.ptrName("2001:db8::1").slice(0, 8), "1.0.0.0.");
    assert.ok(!L.isPublicIP("10.1.2.3") && L.isPublicIP("8.8.8.8") && !L.isPublicIP("fe80::1"));
});
await test("joinTxt", () => {
    assert.equal(joinTxt('"v=spf1 ip4:1.2.3.4 " "-all"'), "v=spf1 ip4:1.2.3.4 -all");
    assert.equal(joinTxt("v=spf1 -all"), "v=spf1 -all");
});
const dns = mockDns();
await test("SPF ip4 pass via redirect", async () => {
    assert.equal((await L.checkSpf("203.0.113.25", "mail.example.com", dns)).result, "pass");
});
await test("SPF include ip6 / a / mx pass", async () => {
    assert.equal((await L.checkSpf("2001:db8:10::9", "example.com", dns)).result, "pass");
    assert.equal((await L.checkSpf("198.51.100.5", "example.com", dns)).result, "pass");
    assert.equal((await L.checkSpf("198.51.100.9", "example.com", dns)).result, "pass");
});
await test("SPF -all fail, none, softfail", async () => {
    assert.equal((await L.checkSpf("198.51.100.77", "example.com", dns)).result, "fail");
    assert.equal((await L.checkSpf("198.51.100.77", "nospf.example", dns)).result, "none");
    const d2 = mockDns({ "TXT soft.example": ["v=spf1 ~all"] });
    assert.equal((await L.checkSpf("1.2.3.4", "soft.example", d2)).result, "softfail");
});
await test("SPF lookup limit / loop → permerror", async () => {
    assert.equal((await L.checkSpf("1.2.3.4", "loop1.example", dns)).result, "permerror");
    const z = {}; for (let i = 0; i < 12; i++) z["TXT d" + i + ".example"] = [`v=spf1 a:x${i}.example include:d${i + 1}.example -all`];
    z["TXT d12.example"] = ["v=spf1 +all"];
    const r = await L.checkSpf("1.2.3.4", "d0.example", mockDns(z));
    assert.equal(r.result, "permerror"); assert.match(r.reason, /too many/);
});
await test("SPF multiple records → permerror; DNS error → temperror", async () => {
    assert.equal((await L.checkSpf("1.2.3.4", "m.example", mockDns({ "TXT m.example": ["v=spf1 -all", "v=spf1 +all"] }))).result, "permerror");
    const bad = { ...dns, txt: async () => { throw new Error("x"); } };
    assert.equal((await L.checkSpf("1.2.3.4", "e.example", bad)).result, "temperror");
});
await test("orgDomain / alignment", () => {
    assert.equal(L.orgDomain("a.b.example.com"), "example.com");
    assert.equal(L.orgDomain("mail.shop.co.uk"), "shop.co.uk");
    assert.ok(L.aligned("mail.example.com", "example.com"));
    assert.ok(!L.aligned("mail.example.com", "example.com", "s"));
});
await test("analyze: trusted AR + forged AR present", async () => {
    const r = await L.analyze(authenticHeaders, dns);
    assert.equal(r.confirm.spf.source.type, "ar"); assert.equal(r.confirm.spf.domain, "mail.example.com");
    assert.equal(r.confirm.dmarc.policy, "reject"); assert.equal(r.confirm.arFlagged.length, 1);
    assert.equal(r.confirm.rdns.result, "neutral"); // PTR smtp25 != HELO out-3, forward-confirmed
    assert.equal(r.verdict.level, "suspicious"); assert.equal(r.verdict.key, "reasonDockedAR");
    assert.equal(r.claim.handoff.hop.helo, "out-3.mail.example.com");
});
await test("analyze: no AR fallback → spoofed", async () => {
    const r = await L.analyze(spoofHeaders, dns);
    assert.equal(r.confirm.spf.source.type, "own"); assert.equal(r.confirm.spf.result, "fail");
    assert.equal(r.confirm.dkim.result, "none"); assert.equal(r.confirm.dmarc.result, "fail");
    assert.equal(r.confirm.rdns.result, "fail"); assert.equal(r.verdict.level, "spoofed");
});
await test("analyze: no AR, unverified aligned DKIM → DMARC neutral, still spoofed by SPF fail", async () => {
    const h = { ...spoofHeaders, "dkim-signature": ["v=1; d=example.com; s=s1; b=x"] };
    const r = await L.analyze(h, dns);
    assert.equal(r.confirm.dkim.result, "neutral"); assert.equal(r.confirm.dmarc.result, "neutral");
    assert.equal(r.verdict.level, "spoofed"); // SPF hard fail, no aligned DKIM *pass*
});
await test("analyze: own SPF pass aligned → authentic", async () => {
    const h = { ...spoofHeaders, received: ["from out-3.mail.example.com (smtp25.example.com [203.0.113.25]) by mx.home.example.net; Wed, 14 Oct 2026"] };
    const r = await L.analyze(h, dns);
    assert.equal(r.confirm.spf.result, "pass"); assert.equal(r.confirm.dmarc.result, "pass");
    assert.equal(r.verdict.level, "authentic");
});
await test("analyze: clean trusted AR → authentic", async () => {
    const h = { ...authenticHeaders, "authentication-results": [authenticHeaders["authentication-results"][0]] };
    const r = await L.analyze(h, dns);
    assert.equal(r.verdict.level, "authentic"); assert.equal(r.confirm.arFlagged.length, 0);
});
await test("AR flagging: same-org internal AR not flagged, forged one flagged, verdict docked", async () => {
    const r = await L.analyze(forgedARHeaders, dns);
    assert.deepEqual(r.confirm.arFlagged.map(a => a.authserv), ["evil.example.org"]);
    assert.equal(r.confirm.arIgnored, 1); // relay2.home.example.net: same org as mx.home.example.net
    assert.equal(r.verdict.level, "suspicious");
});
await test("verdict docking: suspicious stays suspicious with AR reason; spoofed unchanged", () => {
    const base = { dmarc: { result: "none" }, dkim: { items: [] }, spf: { result: "neutral" }, arFlagged: [{}] };
    const v = L.verdict("example.com", base);
    assert.equal(v.level, "suspicious"); assert.equal(v.key, "reasonMixedAR");
    assert.equal(L.verdict("example.com", { ...base, dmarc: { result: "fail" } }).level, "spoofed");
    assert.equal(L.verdict("example.com", { ...base, arFlagged: [] }).key, "reasonMixed");
});
await test("analyze: own-check resolver names are reported", async () => {
    const f = async () => ({ ok: true, json: async () => ({ Status: 0, Answer: [] }) });
    const r = await L.analyze(spoofHeaders, createDns(f, [{ name: "R1", url: "https://r1.example/q" }]));
    assert.deepEqual(r.confirm.spf.source.resolvers, ["R1"]); assert.deepEqual(r.confirm.rdns.source.resolvers, ["R1"]);
});

// ---- resolver fallback ----
const OK = answer => ({ ok: true, json: async () => ({ Status: 0, Answer: answer }) });
const RS = [{ name: "A", url: "https://a.example/q" }, { name: "B", url: "https://b.example/q" }, { name: "C", url: "https://c.example/q" }];
const host = u => new URL(u).hostname[0].toUpperCase();
await test("fallback: network error → next resolver, order respected", async () => {
    const calls = [];
    const f = async u => { calls.push(host(u)); if (host(u) === "A") throw new TypeError("network"); return OK([{ type: 1, data: "192.0.2.1" }]); };
    const d = createDns(f, RS); assert.deepEqual(await d.a("x.example"), ["192.0.2.1"]);
    assert.deepEqual(calls, ["A", "B"]); assert.deepEqual([...d.used], ["B"]);
});
await test("fallback: HTTP error and SERVFAIL → next resolver", async () => {
    const f = async u => host(u) === "A" ? { ok: false, status: 503 } : host(u) === "B" ? { ok: true, json: async () => ({ Status: 2 }) } : OK([{ type: 1, data: "192.0.2.3" }]);
    const d = createDns(f, RS); assert.deepEqual(await d.a("x.example"), ["192.0.2.3"]); assert.deepEqual([...d.used], ["C"]);
});
await test("fallback: timeout → next resolver", async () => {
    const f = (u, o) => host(u) === "A" ? new Promise(() => {}) : Promise.resolve(OK([{ type: 1, data: "192.0.2.4" }]));
    const t0 = Date.now(); const d = createDns(f, RS, 100);
    assert.deepEqual(await d.a("x.example"), ["192.0.2.4"]); assert.ok(Date.now() - t0 < 1000);
});
await test("no fallback on NXDOMAIN", async () => {
    const calls = [];
    const f = async u => { calls.push(host(u)); return { ok: true, json: async () => ({ Status: 3 }) }; };
    assert.deepEqual(await createDns(f, RS).a("nx.example"), []); assert.deepEqual(calls, ["A"]);
});
await test("all resolvers failing → error", async () => {
    await assert.rejects(createDns(async () => { throw new Error("down"); }, RS).a("x.example"), /All resolvers failed/);
});
await test("shipped resolver list matches manifest host permissions exactly", async () => {
    const { RESOLVERS } = await import("../src/messagePopup/dns.js");
    const { readFileSync } = await import("node:fs");
    const m = JSON.parse(readFileSync(new URL("../src/manifest.json", import.meta.url)));
    const hosts = m.permissions.filter(p => p.startsWith("https://")).sort();
    assert.deepEqual(hosts, RESOLVERS.map(r => new URL(r.url).origin + "/*").sort());
    assert.equal(RESOLVERS[0].name, "Cloudflare"); assert.equal(RESOLVERS.at(-1).name, "Google");
});

await test("createDns parses Google JSON and Cloudflare header", async () => {
    let seen;
    const fake = async (url, opts) => { seen = { url, opts }; return { ok: true, json: async () => ({ Status: 0, Answer: [{ type: 5, data: "x." }, { type: 16, data: '"v=spf1 " "-all"' }] }) }; };
    assert.deepEqual(await createDns(fake).txt("a.example"), ["v=spf1 -all"]);
    assert.match(seen.url, /^https:\/\/cloudflare-dns\.com\/dns-query\?name=a\.example&type=TXT$/);
    assert.equal(seen.opts.headers.accept, "application/dns-json");
    const nx = async () => ({ ok: true, json: async () => ({ Status: 3 }) });
    assert.deepEqual(await createDns(nx).a("c.example"), []);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
