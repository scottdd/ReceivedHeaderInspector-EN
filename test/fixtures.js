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

// ---- IPv6 fixtures (documentation prefix 2001:db8::/32 only) ----
export const v6Headers = {
    "received": [
        "from mail6.example.com (mail6.example.com [IPv6:2001:db8:25::5])\r\n\tby mx.home.example.net (Postfix) with ESMTPS id 9F; Thu, 15 Oct 2026 09:00:00 -0500",
        "from internal-filter.home.example.net (fd00::7) by mx.home.example.net; Thu, 15 Oct 2026 14:00:00 +0000"
    ],
    "authentication-results": ["mx.home.example.net; spf=pass smtp.mailfrom=bounce@v6.example.com; dkim=none; dmarc=none header.from=v6.example.com"],
    "from": ["V6 Sender <hello@v6.example.com>"],
    "return-path": ["<bounce@v6.example.com>"]
};
export const v6NoArHeaders = {
    "received": [
        "from mail6.example.com (mail6.example.com [IPv6:2001:db8:25::5]) by mx.home.example.net (Postfix) with ESMTPS; Thu, 15 Oct 2026 09:00:00 -0500"
    ],
    "from": ["V6 Sender <hello@v6.example.com>"],
    "return-path": ["<bounce@v6.example.com>"],
    "dkim-signature": ["v=1; d=v6.example.com; s=k1; b=x"]
};
Object.assign(zone, {
    "TXT v6.example.com": ["v=spf1 a/24//64 mx//48 -all"],
    "AAAA v6.example.com": ["2001:db8:25::1"],
    "A v6.example.com": ["192.0.2.1"],
    "MX v6.example.com": ["10 mx.v6.example.com."],
    "AAAA mx.v6.example.com": ["2001:db8:99::3"],
    "TXT _dmarc.v6.example.com": ["v=DMARC1; p=quarantine"],
    // 2001:db8:25::5 -> nibble PTR
    "PTR 5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.5.2.0.0.8.b.d.0.1.0.0.2.ip6.arpa": ["mail6.example.com.", "alt6.example.com."],
    "AAAA mail6.example.com": ["2001:db8:25::5"],
    "AAAA alt6.example.com": ["2001:db8:25::99"],
    "TXT map.example": ["v=spf1 ip4:192.0.2.0/24 -all"],
    "TXT six.example": ["v=spf1 ip6:2001:DB8:0:0:0:0:0:0/32 -all"],
    "TXT onlyv4.example": ["v=spf1 ip4:192.0.2.0/24 a -all"],
    "A onlyv4.example": ["192.0.2.55"],
});

// ---- Synthetic big-sender formats (documentation addresses; modelled on Microsoft 365 / Gmail header shapes) ----
export const m365Headers = {
    "received": [
        "from NAM02-BN1-obe.outbound.protection.outlook.example (mail-bn1nam02on20700.outbound.protection.outlook.example [2001:db8:f400:fe::700])\r\n by mx.home.example.net (Postfix) with ESMTPS id ABC123; Thu, 15 Oct 2026 10:09:00 -0500 (CDT)",
        "from DM6PR12CA0001.example.org (2001:db8:10b6:5::2) by DM6PR12MB0002.example.org (2001:db8:10b6:5::3) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9; Thu, 15 Oct 2026 15:09:00 +0000",
        "from CH0PR00MB0001.example.org (2001:db8:10b6:5::4) by DM6PR12CA0001.example.org with HTTPS; Thu, 15 Oct 2026 15:08:59 +0000"
    ],
    "authentication-results": [
        "mx.home.example.net;\r\n\tdkim=pass (2048-bit key; unprotected) header.d=corp.example.com header.i=@corp.example.com header.b=\"AbCd1234\";\r\n\tdkim=pass (2048-bit key; unprotected) header.d=corp.onmicrosoft.example header.i=@corp.onmicrosoft.example header.b=\"EfGh5678\";\r\n\tdmarc=pass (p=reject dis=none) header.from=corp.example.com;\r\n\tspf=pass smtp.mailfrom=corp.example.com",
        "spf=pass (sender IP is 2001:db8:f400:fe::700) smtp.mailfrom=corp.example.com; dkim=pass (signature was verified) header.d=corp.example.com; dmarc=pass action=none header.from=corp.example.com;compauth=pass reason=100"
    ],
    "from": ["\"Pat Example\" <pat@corp.example.com>"],
    "return-path": ["<pat@corp.example.com>"],
    "dkim-signature": ["v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.example.com; s=selector1; h=From:Date:Subject; bh=x; b=y",
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.onmicrosoft.example; s=selector1-corp-example-com; h=From:Date; bh=x; b=y"]
};
export const gmailHeaders = {
    "received": [
        "from mail-sor-f41.google.example (mail-sor-f41.google.example. [2001:db8:4864:20::f41])\r\n        by mx.home.example.net (Postfix) with ESMTPS id 77\r\n        for <me@home.example.net>; Thu, 15 Oct 2026 10:00:00 -0500 (CDT)",
        "by 2002:a05:6a20:1234:b0:1a:2b:3c with SMTP id abc123csp1;\r\n        Thu, 15 Oct 2026 08:00:00 -0700 (PDT)"
    ],
    "authentication-results": ["mx.home.example.net;\r\n\tdkim=pass (2048-bit key) header.d=gmail.example header.s=20230601 header.b=Zz;\r\n\tspf=pass smtp.mailfrom=someone@gmail.example;\r\n\tdmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.example"],
    "from": ["Some One <someone@gmail.example>"],
    "return-path": ["<someone@gmail.example>"]
};
Object.assign(zone, { "PTR 7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.0.0.4.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa": [] });

// ---- Internal (same-tenant Microsoft 365) message: synthetic copy of a real coworker message ----
// Example names only (contoso.example, example tenant GUID); host names/IDs follow the Exchange Online shapes.
export const internalHeaders = {
    "received": [
        "from DS7PR19MB5686.namprd19.prod.outlook.com (::1) by BYAPR19MB2967.namprd19.prod.outlook.com with HTTPS; Thu, 15 Oct 2026 10:41:52 +0000",
        "from PH8PR19MB6951.namprd19.prod.outlook.com (2603:10b6:510:22c::21) by DS7PR19MB5686.namprd19.prod.outlook.com\r\n (2603:10b6:8:71::15) with Microsoft SMTP Server (version=TLS1_2,\r\n cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.21.522.14; Thu, 15 Oct 2026 10:41:50 +0000",
        "from PH8PR19MB6951.namprd19.prod.outlook.com ([fe80::46a1:74eb:70a2:6ca]) by PH8PR19MB6951.namprd19.prod.outlook.com\r\n ([fe80::46a1:74eb:70a2:6ca%4]) with mapi id 15.21.0522.012; Thu, 15 Oct 2026 10:41:50 +0000"
    ],
    "x-ms-exchange-organization-authas": ["Internal"],
    "x-ms-exchange-organization-authmechanism": ["04"],
    "x-ms-exchange-organization-authsource": ["PH8PR19MB6951.namprd19.prod.outlook.com"],
    "authentication-results": ["mx.microsoft.com 1; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=contoso.example;"],
    "x-ms-exchange-crosstenant-authas": ["Internal"],
    "x-ms-exchange-crosstenant-id": ["00000000-1111-2222-3333-444444444444"],
    "x-forefront-antispam-report": ["CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR19MB6951.namprd19.prod.outlook.com;PTR:;CAT:NONE;SFS:;DIR:INT;"],
    "from": ["Alex Coworker <alex@contoso.example>"],
    "subject": ["Lunch on Friday?"]
};
export const forgedInternalExternalHop = {
    ...internalHeaders,
    "received": ["from mail.attacker.example (mail.attacker.example [203.0.113.50]) by BYAPR19MB2967.namprd19.prod.outlook.com with ESMTPS; Thu, 15 Oct 2026 10:42:00 +0000",
        ...internalHeaders.received],
    "authentication-results": ["mx.microsoft.com 1; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=contoso.example;"]
};
export const forgedInternalForeignAR = {
    ...internalHeaders,
    "authentication-results": ["mx.evil.example.org; spf=pass smtp.mailfrom=contoso.example; dmarc=pass header.from=contoso.example"]
};
