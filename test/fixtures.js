// Sample headers (getFull-style: lowercase keys, array values) and a fake DNS zone.
export const authenticHeaders = {
    "received": [
        "from out-3.mail.example.com (out-3.mail.example.com [203.0.113.25])\r\n\tby mx.home.example.net (Postfix) with ESMTPS id 4A1B2C3\r\n\tfor <scott@home.example.net>; Wed, 14 Oct 2026 18:02:11 -0500 (CDT)",
        "from relay.mail.example.com (relay.mail.example.com [203.0.113.10]) by out-3.mail.example.com with ESMTP; Wed, 14 Oct 2026 23:02:10 +0000",
        "from app01.internal.example.com ([192.0.2.14]) by relay.mail.example.com; Wed, 14 Oct 2026 23:02:09 +0000"
    ],
    "authentication-results": [
        "mx.home.example.net; spf=pass (sender IP is 203.0.113.25) smtp.mailfrom=bounce-8812@mail.example.com smtp.helo=out-3.mail.example.com; dkim=pass (2048-bit key) header.d=example.com header.s=s1 header.b=AbCd; dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=example.com",
        "evil.example.org; spf=pass smtp.mailfrom=x@evil.example.org; dmarc=pass header.from=example.com"
    ],
    "from": ["Example Billing <billing@example.com>"],
    "return-path": ["<bounce-8812@mail.example.com>"],
    "dkim-signature": ["v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;\r\n s=s1; h=from:to:subject; bh=xyz; b=abc"],
    "subject": ["Your invoice #10442 is ready"]
};
export const spoofHeaders = {
    "received": [
        "from localhost (localhost [127.0.0.1]) by mx.home.example.net (Postfix); Wed, 14 Oct 2026 18:10:00 -0500",
        "from mailer.example.org (unknown [198.51.100.77]) by mx.home.example.net (Postfix) with ESMTP; Wed, 14 Oct 2026 18:09:59 -0500"
    ],
    "from": ["\"Example Billing\" <billing@example.com>"],
    "return-path": ["<x@example.com>"],
    "subject": ["Urgent: update your payment details"]
};
export const zone = {
    "TXT example.com": ["v=spf1 ip4:203.0.113.0/26 include:_spf.example.net -all"],
    "TXT mail.example.com": ["v=spf1 redirect=example.com"],
    "TXT _spf.example.net": ["v=spf1 ip6:2001:db8:10::/48 a:mta.example.net mx -all"],
    "A mta.example.net": ["198.51.100.5"],
    "MX _spf.example.net": ["10 mx1.example.net."],
    "A mx1.example.net": ["198.51.100.9"],
    "TXT _dmarc.example.com": ["v=DMARC1; p=reject; adkim=r; aspf=r"],
    "PTR 25.113.0.203.in-addr.arpa": ["smtp25.example.com."],
    "A smtp25.example.com": ["203.0.113.25"],
    "PTR 77.100.51.198.in-addr.arpa": ["host77.isp.example."],
    "A host77.isp.example": ["198.51.100.78"],
    "TXT loop1.example": ["v=spf1 include:loop2.example -all"],
    "TXT loop2.example": ["v=spf1 include:loop1.example -all"],
};
export function mockDns(z = zone) {
    const q = (t, n) => Promise.resolve((z[t + " " + n.replace(/\.$/, "").toLowerCase()] || []).slice());
    return { txt: n => q("TXT", n), a: n => q("A", n), aaaa: n => q("AAAA", n),
        mx: async n => (await q("MX", n)).map(d => d.split(/\s+/).pop().replace(/\.$/, "")),
        ptr: async n => (await q("PTR", n)).map(d => d.replace(/\.$/, "")) };
}

export const forgedARHeaders = {
    ...authenticHeaders,
    "authentication-results": [
        authenticHeaders["authentication-results"][0],
        "evil.example.org; spf=pass smtp.mailfrom=x@evil.example.org; dmarc=pass header.from=example.com",
        "relay2.home.example.net; dkim=pass header.d=example.com"
    ]
};

// Clean sample: only the trusted Authentication-Results header (used for documentation screenshots).
export const cleanHeaders = {
    ...authenticHeaders,
    "authentication-results": [authenticHeaders["authentication-results"][0]]
};
