import { analyze, extractClaim } from "./lib.js";
import { createDns } from "./dns.js";

const t = (key, ...subs) => browser.i18n.getMessage(key, subs.map(String)) || key;
const $ = id => document.getElementById(id);

function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
}
// Collapsible cell: first line always visible, extra lines shown when expanded.
function cell(main, extras = [], mono = false) {
    const c = el("div", "x" + (mono ? " mono" : ""));
    c.appendChild(el("span", null, main));
    for (const x of extras) {
        if (!x) continue;
        c.appendChild(document.createElement("br"));
        c.appendChild(el("span", x.cls || "sub", x.text));
    }
    c.addEventListener("click", () => c.classList.toggle("open"));
    return c;
}
function localizePage() {
    document.querySelectorAll("[data-i18n]").forEach(e => { e.textContent = t(e.dataset.i18n); });
    document.title = t("actionTitle");
}
function badgeClass(r) {
    if (r === "pass") return "pass";
    if (["fail", "softfail", "permerror"].includes(r)) return "fail";
    return "neutral";
}
function sourceText(s) { return s.type === "ar" ? t("srcAR", s.by) : t("srcOwn"); }

function renderClaim(c) {
    const g = $("claim");
    const add = (label, node) => { g.appendChild(el("div", "k", label)); g.appendChild(node); };
    add(t("labelSubject"), cell(c.subject || t("notPresent")));
    const fromMain = c.from.name ? `${c.from.name} <${c.from.address}>` : (c.from.address || t("notPresent"));
    add(t("labelFrom"), cell(fromMain, [c.from.domain && { text: t("fromDomain", c.from.domain) }]));
    add(t("labelReturnPath"), c.returnPath && c.returnPath.address
        ? cell(c.returnPath.address, [{ text: t("envelopeDomain", c.returnPath.domain) }], true)
        : cell(t("notPresent")));
    add(t("labelDkimD"), c.dkim.length
        ? cell(c.dkim.map(s => s.d).join(", "), c.dkim.map(s => ({ text: `d=${s.d}; s=${s.s}` })), true)
        : cell(t("dkimNone")));
    const h = c.handoff?.hop;
    add(t("labelHandoff"), h
        ? cell(`${h.helo || "?"} [${h.ip || "?"}]`, [
            { text: t("heloLine", h.helo || "?") },
            { text: t("ipLine", h.ip || "?") },
            { text: t("rdnsInHeader", h.rdns || "—") },
            { text: t("byLine", h.by || "?") }], true)
        : cell(t("noHandoff")));
    add(t("labelSender"), cell(c.sender || t("notPresent")));
}

function confirmRow(label, result, main, extras, source) {
    const row = el("div", "row");
    row.appendChild(el("span", "badge " + badgeClass(result), (result || "none").toUpperCase()));
    row.appendChild(el("span", "k", label));
    row.appendChild(cell(main, [...extras, { text: sourceText(source), cls: "src" }]));
    $("confirm").appendChild(row);
}

function renderConfirm(c) {
    const { spf, dkim, dmarc, rdns } = c;
    const spfMain = spf.source.type === "ar"
        ? t("spfAR", spf.domain || "?")
        : (spf.ip ? t("spfOwn", spf.ip, spf.domain || "?") : t("noHandoff"));
    confirmRow(t("labelSPF"), spf.result, spfMain,
        [spf.mechanism && { text: t("spfMatched", spf.mechanism) }, spf.reason && { text: spf.reason }].filter(Boolean), spf.source);

    let dkimMain, dkimExtras = [];
    if (dkim.source.type === "ar") {
        dkimMain = dkim.items.map(i => `d=${i.d || "?"} ${i.result}`).join(", ");
    } else dkimMain = dkim.notVerified ? t("dkimNotVerified") : t("dkimNone");
    confirmRow(t("labelDKIM"), dkim.result, dkimMain, dkimExtras, dkim.source);

    let dmarcMain;
    if (dmarc.source.type === "ar") dmarcMain = t("dmarcAR", dmarc.domain || "?", dmarc.policy || "?");
    else if (dmarc.result === "none") dmarcMain = t("dmarcNoRecord", dmarc.domain || "?");
    else if (dmarc.result === "pass") dmarcMain = t("dmarcOwnPass", dmarc.domain, dmarc.policy);
    else if (dmarc.result === "neutral") dmarcMain = t("dmarcOwnNeutral", dmarc.policy);
    else if (dmarc.result === "fail") dmarcMain = t("dmarcOwnFail", dmarc.policy);
    else dmarcMain = t("dnsError");
    confirmRow(t("labelDMARC"), dmarc.result, dmarcMain, dmarc.orgNote ? [{ text: t("orgNote") }] : [], dmarc.source);

    confirmRow(t("labelRDNS"), rdns.result, t(rdns.key, ...rdns.subs), [], rdns.source);
    if (c.arIgnored) $("arnote").textContent = t("arIgnored", c.arIgnored);
}

function renderVerdict(v) {
    const box = $("verdict");
    box.className = "verdict " + v.level;
    box.textContent = "";
    const icon = { authentic: "✔ ", suspicious: "⚠ ", spoofed: "✖ " }[v.level];
    box.appendChild(el("b", null, icon + t("verdict_" + v.level)));
    box.appendChild(el("span", null, t(v.key, ...v.subs)));
}

function renderPath(c) {
    $("pathTitle").textContent = t("deliveryPath", c.received.length);
    const ol = $("hops");
    c.received.forEach((r, i) => {
        const li = el("li");
        const from = r.hasFrom ? `${r.helo || "?"}${r.ip ? " [" + r.ip + "]" : ""}` : "—";
        li.appendChild(el("span", null, `${from} → ${r.by || "?"}`));
        li.appendChild(document.createElement("br"));
        const sub = el("span", "sub", r.date);
        if (c.handoff && c.handoff.index === i) { sub.appendChild(document.createTextNode(" · ")); sub.appendChild(el("b", null, t("handoffTag"))); }
        li.appendChild(sub);
        ol.appendChild(li);
    });
}

async function getDisplayedMessage() {
    const [tab] = await messenger.tabs.query({ active: true, currentWindow: true });
    if (messenger.messageDisplay.getDisplayedMessage) {
        const m = await messenger.messageDisplay.getDisplayedMessage(tab.id);
        if (m) return m;
    }
    if (messenger.messageDisplay.getDisplayedMessages) {
        const list = await messenger.messageDisplay.getDisplayedMessages(tab.id);
        return (list?.messages || list || [])[0] || null;
    }
    return null;
}

async function main() {
    localizePage();
    try {
        const message = await getDisplayedMessage();
        if (!message) throw new Error("No message displayed.");
        const full = await messenger.messages.getFull(message.id);
        const headers = full.headers || {};
        const claim = extractClaim(headers);
        renderClaim(claim);
        renderPath(claim);
        const result = await analyze(headers, createDns());
        renderConfirm(result.confirm);
        renderVerdict(result.verdict);
    } catch (e) {
        console.error("Received Header Inspector:", e);
        const box = $("verdict");
        box.className = "verdict pending";
        box.textContent = t("errorGeneric", String(e?.message || e));
    }
}

main();
