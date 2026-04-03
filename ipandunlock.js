/**
 * IP multi-source purity check widget + Streaming/AI unlock detection
 * Sources: IPPure / ipapi.is / IP2Location / Scamalytics / DB-IP / ipregistry / ipinfo
 * Unlock: ChatGPT / Gemini / Netflix / TikTok / YouTube Premium
 * Env: POLICY, MARK_IP
 * Layout: Custom Left-Aligned Order + Compact fit
 */
export default async function (ctx) {
    var BG_COLOR = { light: '#FFFFFF', dark: '#1C1C1E' };
    var C_TITLE = { light: '#1A1A1A', dark: '#FFD700' };
    var C_SUB = { light: '#666666', dark: '#B0B0B0' }; // 还原 A 脚本的次要文本色
    var C_MAIN = { light: '#1A1A1A', dark: '#FFFFFF' };
    var C_GREEN = { light: '#32D74B', dark: '#32D74B' };
    var C_YELLOW = { light: '#FFD60A', dark: '#FFD60A' };
    var C_ORANGE = { light: '#FF9500', dark: '#FF9500' };
    var C_RED = { light: '#FF3B30', dark: '#FF3B30' };
    var C_ICON_IP = { light: '#007AFF', dark: '#0A84FF' };
    var C_ICON_LO = { light: '#5856D6', dark: '#5E5CE6' };
    var C_ICON_SC = { light: '#AF52DE', dark: '#BF5AF2' };
    var C_BLUE = { light: '#007AFF', dark: '#0A84FF' };

    var policy = ctx.env.POLICY || "";
    var markIP = (ctx.env.MARK_IP || "").toLowerCase() === "true";

    var BASE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";

    async function safe(fn) { try { return await fn(); } catch (e) { return null; } }

    async function get(url, headers) {
        var opts = { timeout: 10000 };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        var res = await ctx.http.get(url, opts);
        return await res.text();
    }

    async function post(url, body, headers) {
        var opts = { timeout: 10000, body: body };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        var res = await ctx.http.post(url, opts);
        return await res.text();
    }

    async function getRaw(url, headers, extraOpts) {
        var opts = { timeout: 10000 };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        if (extraOpts) { for (var k in extraOpts) opts[k] = extraOpts[k]; }
        return await ctx.http.get(url, opts);
    }

    function jp(s) { try { return JSON.parse(s); } catch (e) { return null; } }
    function ti(v) { var n = Number(v); return Number.isFinite(n) ? Math.round(n) : null; }

    function maskIP(ip) {
        if (!ip) return '';
        if (ip.includes('.')) { var p = ip.split('.'); return p[0] + '.' + p[1] + '.*.*'; }
        var p6 = ip.split(':'); return p6[0] + ':' + p6[1] + ':*:*:*:*:*:*';
    }

    function toFlag(code) {
        if (!code) return '\uD83C\uDF10';
        var c = code.toUpperCase();
        if (c === 'TW') c = 'CN';
        if (c.length !== 2) return '\uD83C\uDF10';
        return String.fromCodePoint(c.charCodeAt(0) + 127397, c.charCodeAt(1) + 127397);
    }

    function fmtISP(isp) {
        if (!isp) return "\u672A\u77E5";
        var s = String(isp).toLowerCase();
        var raw = String(isp).replace(/\s*\(\u4E2D\u56FD\)\s*/, "").replace(/\s+/g, " ").trim();
        if (/(^|[\s-])(cmcc|cmnet|cmi|mobile)\b|\u79FB\u52A8/.test(s)) return "\u4E2D\u56FD\u79FB\u52A8";
        if (/(^|[\s-])(chinanet|telecom|ctcc|ct)\b|\u7535\u4FE1/.test(s)) return "\u4E2D\u56FD\u7535\u4FE1";
        if (/(^|[\s-])(unicom|cncgroup|netcom|link)\b|\u8054\u901A/.test(s)) return "\u4E2D\u56FD\u8054\u901A";
        if (/(^|[\s-])(cbn|broadcast)\b|\u5E7F\u7535/.test(s)) return "\u4E2D\u56FD\u5E7F\u7535";
        return raw || "\u672A\u77E5";
    }

    // ===================== 评分函数 =====================

    function gradeIppure(score) {
        var s = ti(score); if (s === null) return null;
        if (s >= 80) return { sev: 4, t: 'IPPure: \u6781\u9AD8 (' + s + ')' };
        if (s >= 70) return { sev: 3, t: 'IPPure: \u9AD8\u5371 (' + s + ')' };
        if (s >= 40) return { sev: 1, t: 'IPPure: \u4E2D\u7B49 (' + s + ')' };
        return { sev: 0, t: 'IPPure: \u4F4E\u5371 (' + s + ')' };
    }

    function gradeIpapi(j) {
        if (!j || !j.company || !j.company.abuser_score) return null;
        var m = String(j.company.abuser_score).match(/([0-9.]+)\s*\(([^)]+)\)/);
        if (!m) return null;
        var pct = Math.round(Number(m[1]) * 10000) / 100 + '%';
        var lv = String(m[2]).trim();
        var map = { 'Very Low': 0, 'Low': 0, 'Elevated': 2, 'High': 3, 'Very High': 4 };
        var sev = map[lv] !== undefined ? map[lv] : 2;
        var tags = [];
        if (j.is_vpn) tags.push('VPN');
        if (j.is_proxy) tags.push('Proxy');
        if (j.is_tor) tags.push('Tor');
        if (j.is_abuser) tags.push('Abuser');
        var tagStr = tags.length ? ' ' + tags.join('/') : '';
        return { sev: sev, t: 'ipapi: ' + lv + ' (' + pct + ')' + tagStr };
    }

    function gradeIp2loc(score) {
        var s = ti(score); if (s === null) return null;
        if (s >= 66) return { sev: 3, t: 'IP2Location: \u9AD8\u5371 (' + s + ')' };
        if (s >= 33) return { sev: 1, t: 'IP2Location: \u4E2D\u5371 (' + s + ')' };
        return { sev: 0, t: 'IP2Location: \u4F4E\u5371 (' + s + ')' };
    }

    function gradeScam(html) {
        if (!html) return null;
        var m = html.match(/Fraud\s*Score[:\s]*(\d+)/i) || html.match(/class="score"[^>]*>(\d+)/i);
        var s = m ? ti(m[1]) : null; if (s === null) return null;
        if (s >= 90) return { sev: 4, t: 'Scamalytics: \u6781\u9AD8 (' + s + ')' };
        if (s >= 60) return { sev: 3, t: 'Scamalytics: \u9AD8\u5371 (' + s + ')' };
        if (s >= 20) return { sev: 1, t: 'Scamalytics: \u4E2D\u5371 (' + s + ')' };
        return { sev: 0, t: 'Scamalytics: \u4F4E\u5371 (' + s + ')' };
    }

    function gradeDbip(html) {
        if (!html) return null;
        var m = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
        var lv = (m ? m[1] : '').toLowerCase();
        if (lv === 'high') return { sev: 3, t: 'DB-IP: \u9AD8\u5371' };
        if (lv === 'medium') return { sev: 1, t: 'DB-IP: \u4E2D\u5371' };
        if (lv === 'low') return { sev: 0, t: 'DB-IP: \u4F4E\u5371' };
        return null;
    }

    function gradeIpreg(j, ipinfoDetected) {
        if (!j || j.code) return null;
        var sec = j.security || {};
        var tags = [];
        if (sec.is_proxy) tags.push('Proxy');
        if (sec.is_tor || sec.is_tor_exit) tags.push('Tor');
        if (sec.is_vpn) tags.push('VPN');
        if (sec.is_abuser) tags.push('Abuser');
        if (ipinfoDetected && ipinfoDetected.length) {
            for (var i = 0; i < ipinfoDetected.length; i++) {
                if (ipinfoDetected[i] === 'Hosting') continue;
                if (tags.indexOf(ipinfoDetected[i]) === -1) tags.push(ipinfoDetected[i]);
            }
        }
        var tagStr = tags.length ? ' ' + tags.join('/') : '';
        if (!tags.length) return { sev: 0, t: 'ipregistry: \u4F4E\u5371' };
        var sev = tags.indexOf('Tor') !== -1 || tags.indexOf('Abuser') !== -1 ? 3 : tags.length >= 2 ? 2 : 1;
        return { sev: sev, t: 'ipregistry: ' + tags.join('/') };
    }

    function sevColor(sev) {
        if (sev >= 4) return C_RED;
        if (sev >= 3) return C_ORANGE;
        if (sev >= 1) return C_YELLOW;
        return C_GREEN;
    }
    function sevIcon(sev) {
        if (sev >= 3) return 'xmark.shield.fill';
        if (sev >= 1) return 'exclamationmark.shield.fill';
        return 'checkmark.shield.fill';
    }
    function sevText(sev) {
        if (sev >= 4) return '\u6781\u9AD8\u98CE\u9669';
        if (sev >= 3) return '\u9AD8\u98CE\u9669';
        if (sev >= 2) return '\u4E2D\u7B49\u98CE\u9669';
        if (sev >= 1) return '\u4E2D\u4F4E\u98CE\u9669';
        return '\u7EAF\u51C0\u4F4E\u5371';
    }

    function usageText(code) {
        if (!code) return '';
        if (code.indexOf('/') !== -1) return code;
        var map = { 'DCH': '\u6570\u636E\u4E2D\u5FC3', 'WEB': '\u6570\u636E\u4E2D\u5FC3', 'SES': '\u6570\u636E\u4E2D\u5FC3', 'CDN': 'CDN', 'MOB': '\u79FB\u52A8\u7F51\u7EDC', 'ISP': '\u5BB6\u5EAD\u5BBD\u5E26', 'COM': '\u5546\u4E1A\u5BBD\u5E26', 'EDU': '\u6559\u80B2\u7F51\u7EDC', 'RES': '\u4F4F\u5B85\u7F51\u7EDC' };
        var parts = code.toUpperCase().split('/');
        var r = [];
        for (var i = 0; i < parts.length; i++) {
            var d = map[parts[i]];
            if (d && r.indexOf(d) === -1) r.push(d);
        }
        return r.length ? r.join('/') + ' (' + code + ')' : code;
    }

    // ===================== 数据获取 =====================

    async function fetchIpapi(ip) { return jp(await get('https://api.ipapi.is/?q=' + encodeURIComponent(ip))); }
    async function fetchDbip(ip) { return await get('https://db-ip.com/' + encodeURIComponent(ip)); }
    async function fetchScam(ip) { return await get('https://scamalytics.com/ip/' + encodeURIComponent(ip)); }

    async function fetchIpreg(ip) {
        var html = await get('https://ipregistry.co', { 'User-Agent': 'Mozilla/5.0' });
        var m = String(html).match(/apiKey="([a-zA-Z0-9]+)"/);
        if (!m) return null;
        return jp(await get('https://api.ipregistry.co/' + encodeURIComponent(ip) + '?hostname=true&key=' + m[1], {
            'Origin': 'https://ipregistry.co', 'Referer': 'https://ipregistry.co/', 'User-Agent': 'Mozilla/5.0'
        }));
    }

    async function fetchIp2loc(ip) {
        var html = await get('https://www.ip2location.io/' + encodeURIComponent(ip));
        var um = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i)
            || html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
        var fm = html.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
        return { usageType: um ? um[1] : null, fraudScore: fm ? ti(fm[1]) : null };
    }

    async function fetchIpinfo(ip) {
        var html = await get('https://ipinfo.io/' + encodeURIComponent(ip), { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' });
        var det = [];
        var types = ['VPN', 'Proxy', 'Tor', 'Relay', 'Hosting'];
        for (var i = 0; i < types.length; i++) {
            if (new RegExp('aria-label="' + types[i] + '\\s+Detected"', 'i').test(html)) det.push(types[i]);
        }
        return det;
    }
    
    async function fetchLocalPublicIP() {
        var res = await getRaw('https://myip.ipip.net/json', { "User-Agent": BASE_UA }, { policy: 'DIRECT', timeout: 6000 });
        if (!res) return {};
        var text = await res.text();
        var json = jp(text) || {};
        return json.data || json;
    }

    // ===================== 解锁检测 =====================

    async function checkChatGPT() {
        try {
            var headRes = await getRaw("https://chatgpt.com", { "User-Agent": BASE_UA }, { redirect: 'manual' });
            var headOk = !!headRes;
            var locationHeader = "";
            if (headRes && headRes.headers) {
                locationHeader = headRes.headers.get ? headRes.headers.get('location') || '' : (headRes.headers.location || headRes.headers.Location || '');
            }
            var webAccessible = headOk && !!locationHeader;

            var iosRes = await getRaw("https://ios.chat.openai.com", { "User-Agent": BASE_UA });
            var iosBody = iosRes ? await iosRes.text() : "";
            var cfDetails = "";
            try {
                var asJson = iosBody ? JSON.parse(iosBody) : null;
                if (asJson && asJson.cf_details) cfDetails = String(asJson.cf_details);
            } catch (e2) {
                var cm = iosBody ? iosBody.match(/"cf_details"\s*:\s*"([^"]*)"/) : null;
                if (cm && cm[1]) cfDetails = cm[1];
            }

            var appBlocked = !iosBody
                || iosBody.indexOf("blocked_why_headline") !== -1
                || iosBody.indexOf("unsupported_country_region_territory") !== -1
                || cfDetails.indexOf("(1)") !== -1
                || cfDetails.indexOf("(2)") !== -1;
            var appAccessible = !!iosBody && !appBlocked;

            if (!webAccessible && !appAccessible) return "\u274C";
            if (appAccessible && !webAccessible) return "APP";
            if (webAccessible && appAccessible) {
                var traceTxt = await get("https://chatgpt.com/cdn-cgi/trace");
                if (traceTxt) {
                    var tm = traceTxt.match(/loc=([A-Z]{2})/);
                    if (tm && tm[1]) return tm[1];
                }
                return "OK";
            }
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    async function checkGemini() {
        try {
            var bodyRaw = 'f.req=[["K4WWud","[[0],[\\"en-US\\"]]",null,"generic"]]';
            var txt = await post('https://gemini.google.com/_/BardChatUi/data/batchexecute', bodyRaw, {
                "User-Agent": BASE_UA, "Accept-Language": "en-US", "Content-Type": "application/x-www-form-urlencoded"
            });
            if (!txt) return "\u274C";

            var m = txt.match(/"countryCode"\s*:\s*"([A-Z]{2})"/i);
            if (m && m[1]) return m[1].toUpperCase();
            m = txt.match(/"requestCountry"\s*:\s*\{[^}]*"id"\s*:\s*"([A-Z]{2})"/i);
            if (m && m[1]) return m[1].toUpperCase();
            m = txt.match(/\[\[\\?"([A-Z]{2})\\?",\\?"S/);
            if (m && m[1]) return m[1].toUpperCase();
            var idx = txt.indexOf('K4WWud');
            if (idx >= 0) {
                var slice = txt.slice(idx, idx + 200);
                var m2 = slice.match(/([A-Z]{2})/);
                if (m2 && m2[1]) return m2[1].toUpperCase();
            }
            return "OK";
        } catch (e) { return "\u274C"; }
    }

    async function checkNetflix() {
        try {
            var titles = [
                "https://www.netflix.com/title/81280792",
                "https://www.netflix.com/title/70143836"
            ];
            var fetchTitle = async function (url) {
                try {
                    var body = await get(url, { "User-Agent": BASE_UA });
                    return body || "";
                } catch (e) { return ""; }
            };
            var bodies = await Promise.all([fetchTitle(titles[0]), fetchTitle(titles[1])]);
            var t1 = bodies[0], t2 = bodies[1];
            if (!t1 && !t2) return "\u274C";

            var oh1 = t1 && /oh no!/i.test(t1);
            var oh2 = t2 && /oh no!/i.test(t2);
            if (oh1 && oh2) return "\uD83C\uDF7F"; 

            var allBodies = [t1, t2];
            for (var i = 0; i < allBodies.length; i++) {
                var b = allBodies[i];
                if (!b) continue;
                var rm = b.match(/"countryCode"\s*:\s*"?([A-Z]{2})"?/);
                if (rm && rm[1]) return rm[1];
            }
            return "OK";
        } catch (e) { return "\u274C"; }
    }

    async function checkTikTok() {
        try {
            var body1 = await get("https://www.tiktok.com/", { "User-Agent": BASE_UA });
            if (body1 && body1.indexOf("Please wait...") !== -1) {
                try { body1 = await get("https://www.tiktok.com/explore", { "User-Agent": BASE_UA }); } catch (e2) { }
            }
            var m1 = body1 ? body1.match(/"region"\s*:\s*"([A-Z]{2})"/) : null;
            if (m1 && m1[1]) return m1[1];

            var body2 = await get("https://www.tiktok.com/", {
                "User-Agent": BASE_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en"
            });
            var m2 = body2 ? body2.match(/"region"\s*:\s*"([A-Z]{2})"/) : null;
            if (m2 && m2[1]) return m2[1];
            if (body1 || body2) return "OK";
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    async function checkYouTube() {
        try {
            var body = await get('https://www.youtube.com/premium', { "User-Agent": BASE_UA, "Accept-Language": "en" });
            if (!body) return "\u274C";
            if (body.indexOf('www.google.cn') !== -1) return "CN";

            var isNotAvailable = body.indexOf('Premium is not available in your country') !== -1 || body.indexOf('YouTube Premium is not available') !== -1;
            var m = body.match(/"contentRegion"\s*:\s*"?([A-Z]{2})"?/);
            var region = (m && m[1]) ? m[1].toUpperCase() : null;
            var isAvailable = body.indexOf('ad-free') !== -1 || body.indexOf('Ad-free') !== -1;

            if (isNotAvailable) return "\u274C";
            if (isAvailable && region) return region;
            if (isAvailable && !region) return "OK";
            if (region) return region;
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    // ===================== 左对齐布局组件 (极度压缩版) =====================

    function LeftRow(iconName, iconColor, label, items, fontSize) {
        var fz = fontSize || 10;
        var children = [
            { type: 'image', src: 'sf-symbol:' + iconName, color: iconColor, width: fz+1, height: fz+1 },
            { type: 'text', text: label, font: { size: fz }, textColor: C_SUB }
        ];
        for (var i = 0; i < items.length; i++) {
            children.push(items[i]);
        }
        // 末尾强制加 spacer，把所有内容向左推（左对齐）
        children.push({ type: 'spacer' });
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
            children: children
        };
    }

    function ScoreRow(grade, fz) {
        var sz = fz || 9; // 默认缩小字号防挤出
        var col = sevColor(grade.sev);
        var parts = grade.t.split(': ');
        var src = parts[0] || grade.t;
        var val = parts[1] || '';
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 3,
            children: [
                { type: 'image', src: 'sf-symbol:' + sevIcon(grade.sev), color: col, width: sz, height: sz },
                { type: 'text', text: src, font: { size: sz }, textColor: C_SUB, maxLines: 1 },
                { type: 'spacer' },
                { type: 'text', text: val, font: { size: sz, weight: 'bold', family: 'Menlo' }, textColor: col, maxLines: 1, minScale: 0.5 },
            ]
        };
    }

    function UnlockRow(name, result, fz) {
        var sz = fz || 9;
        var isOk = result !== "\u274C" && result !== "\uD83C\uDF7F" && result !== "\u23F3" && result !== "CN";
        var color = isOk ? C_GREEN : (result === "\uD83C\uDF7F" || result === "\u23F3" || result === "APP") ? C_YELLOW : C_RED;
        var icon = isOk ? 'checkmark.circle.fill' : (result === "\uD83C\uDF7F" || result === "\u23F3" || result === "APP") ? 'exclamationmark.circle.fill' : 'xmark.circle.fill';
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 3,
            children: [
                { type: 'image', src: 'sf-symbol:' + icon, color: color, width: sz, height: sz },
                { type: 'text', text: name, font: { size: sz }, textColor: C_SUB },
                { type: 'spacer' },
                { type: 'text', text: result, font: { size: sz, weight: 'bold' }, textColor: color, maxLines: 1 },
            ]
        };
    }

    // ===================== 主逻辑 =====================

    try {
        var ip = null, cachedIpapi = null;
        try {
            var d_ip = jp(await get('http://ip-api.com/json?lang=zh-CN'));
            ip = d_ip && (d_ip.query || d_ip.ip);
        } catch (e) { }
        if (!ip) {
            try { cachedIpapi = jp(await get('https://api.ipapi.is/')); ip = cachedIpapi && cachedIpapi.ip; } catch (e) { }
        }
        if (!ip) return { type: 'widget', children: [{ type: 'text', text: '获取 IP 失败' }] };

        var ippureScore = null;
        try { var d2 = jp(await get('https://my.ippure.com/v1/info')); ippureScore = d2 && d2.fraudScore; } catch (e) { }

        // 并行查询
        var results = await Promise.all([
            cachedIpapi ? Promise.resolve(cachedIpapi) : safe(function () { return fetchIpapi(ip); }),
            safe(function () { return fetchIp2loc(ip); }),
            safe(function () { return fetchIpinfo(ip); }),
            safe(function () { return fetchDbip(ip); }),
            safe(function () { return fetchScam(ip); }),
            safe(function () { return fetchIpreg(ip); }),
            safe(checkChatGPT),
            safe(checkGemini),
            safe(checkNetflix),
            safe(checkTikTok),
            safe(checkYouTube),
            safe(fetchLocalPublicIP)
        ]);
        var rIpapi = results[0], rIp2loc = results[1], rIpinfo = results[2];
        var rDbip = results[3], rScam = results[4], rIpreg = results[5];
        var uGPT = results[6] || "\u274C", uGemini = results[7] || "\u274C";
        var uNetflix = results[8] || "\u274C", uTikTok = results[9] || "\u274C";
        var uYouTube = results[10] || "\u274C";
        var localIpData = results[11] || {};

        var ipapiD = rIpapi || {};
        var asnText = (ipapiD.asn && ipapiD.asn.asn) ? ('AS' + ipapiD.asn.asn + ' ' + (ipapiD.asn.org || '')).trim() : '\u672A\u77E5';
        var cc = (ipapiD.location && ipapiD.location.country_code) || '';
        var country = (ipapiD.location && ipapiD.location.country) || '';
        var city = (ipapiD.location && ipapiD.location.city) || '';
        var loc = (toFlag(cc) + ' ' + country + ' ' + city).trim() || '\u672A\u77E5\u4F4D\u7F6E';
        var hosting = usageText(rIp2loc && rIp2loc.usageType);

        // ===================== 本地网络及公网 IP 逻辑 =====================
        var d_ctx = ctx.device || {};
        var wifiSsid = (d_ctx.wifi && d_ctx.wifi.ssid) ? d_ctx.wifi.ssid : "";
        var cellularRadio = (d_ctx.cellular && d_ctx.cellular.radio) ? d_ctx.cellular.radio : "";
        
        var rawISP = (Array.isArray(localIpData.location) ? localIpData.location[localIpData.location.length-1] : "") || (ipapiD.asn && ipapiD.asn.org) || "";
        var currentISP = wifiSsid || fmtISP(rawISP);

        if (!wifiSsid && currentISP.indexOf("\u7535\u4FE1") !== -1 && cellularRadio) {
            var map = { GPRS:"2G", EDGE:"2G", LTE:"4G", "LTE-CA":"4G+", NR:"5G" };
            currentISP = currentISP + " " + (map[cellularRadio] || cellularRadio);
        }
        var netIcon = wifiSsid ? 'wifi' : (cellularRadio ? 'antenna.radiowaves.left.and.right' : 'wifi.slash');

        var locStr = "";
        if (Array.isArray(localIpData.location)) {
            var tags = localIpData.location.filter(function(i) {
                return i && !/\u7535\u4FE1|\u79FB\u52A8|\u8054\u901A|\u5E7F\u7535|IP|China|\u4E2D\u56FD|\u6570\u636E\u4E2D\u5FC3/i.test(i);
            });
            var uniqueTags = [];
            for (var i=0; i<tags.length; i++) {
                if (uniqueTags.indexOf(tags[i]) === -1) uniqueTags.push(tags[i]);
            }
            if (uniqueTags.length >= 2) {
                locStr = uniqueTags[uniqueTags.length - 2] + " - " + uniqueTags[uniqueTags.length - 1];
            } else if (uniqueTags.length === 1) {
                locStr = uniqueTags[0];
            }
        }
        var localPublicIpContent = [localIpData.ip || "\u672A\u83B7\u53D6", locStr].filter(Boolean).join(" - ");

        // ===================== 生成纯净的刷新时间文本 =====================
        var nowObj = new Date();
        var timeH = nowObj.getHours().toString().padStart(2, '0');
        var timeM = nowObj.getMinutes().toString().padStart(2, '0');
        var timeS = nowObj.getSeconds().toString().padStart(2, '0');
        var refreshTimeStr = timeH + ':' + timeM + ':' + timeS;


        // ===================== 多源评分组装 =====================
        var grades = [
            gradeIppure(ippureScore),
            gradeIpapi(rIpapi),
            gradeIp2loc(rIp2loc && rIp2loc.fraudScore),
            gradeScam(rScam),
            gradeDbip(rDbip),
            gradeIpreg(rIpreg, rIpinfo),
        ].filter(Boolean);

        var maxSev = 0;
        for (var i = 0; i < grades.length; i++) {
            if (grades[i].sev > maxSev) maxSev = grades[i].sev;
        }
        var showIP = markIP ? maskIP(ip) : ip;

        // 第三行：落地IP + DCH数据中心 + 检测盾牌评分结果 全部紧凑排列
        var mProxyItems = [
            { type: 'text', text: showIP, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN, maxLines: 1, minScale: 0.8 }
        ];
        if (hosting) {
            mProxyItems.push({ type: 'text', text: '| ' + hosting, font: { size: 9, weight: 'bold' }, textColor: C_SUB, maxLines: 1, minScale: 0.8 });
        }
        mProxyItems.push({ type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), color: sevColor(maxSev), width: 9, height: 9 });
        mProxyItems.push({ type: 'text', text: sevText(maxSev), font: { size: 9, weight: 'bold' }, textColor: sevColor(maxSev), maxLines: 1, minScale: 0.8 });

        var family = ctx.widgetFamily || 'systemMedium';

        // ===================== systemMedium - 重新排版 (极度抗重叠) =====================
        if (family === 'systemMedium') {
            
            // 第一行：左侧当前网络，右侧还原 A 脚本 UI 风格：timer 图标 + C_SUB 次要色 + 常规字体
            var row1Network = {
                type: 'stack', direction: 'row', alignItems: 'center', gap: 5,
                children: [
                    { type: 'image', src: 'sf-symbol:' + netIcon, color: C_TITLE, width: 12, height: 12 },
                    { type: 'text', text: currentISP, font: { size: 12, weight: 'heavy' }, textColor: C_TITLE, maxLines: 1 },
                    { type: 'spacer' },
                    { 
                        type: 'stack', direction: 'row', alignItems: 'center', gap: 2, children: [
                            { type: 'image', src: 'sf-symbol:timer', color: C_SUB, width: 12, height: 12 },
                            { type: 'text', text: refreshTimeStr, font: { size: 12, weight: 'regular' }, textColor: C_SUB }
                        ]
                    }
                ]
            };

            // 底部左侧：解锁检测 (共5行)
            var unlocksAll = [
                UnlockRow('GPT', uGPT, 9),
                UnlockRow('Gemini', uGemini, 9),
                UnlockRow('YouTube', uYouTube, 9),
                UnlockRow('\u5948\u98DE', uNetflix, 9),
                UnlockRow('TikTok', uTikTok, 9)
            ];

            // 底部右侧：多源评分 (可多达6行，字号9不会超出边界)
            var scoreRows = [];
            for (var i = 0; i < grades.length; i++) {
                scoreRows.push(ScoreRow(grades[i], 9));
            }

            return {
                // 大幅缩减外边距(padding)和行距(gap)，为内容腾出绝对足够的物理空间
                type: 'widget', padding: [8, 12, 8, 12], gap: 3, backgroundColor: BG_COLOR,
                children: [
                    row1Network, // 第 1 行：网络 + 1:1复刻的刷新时间
                    LeftRow('location.circle.fill', C_BLUE, '本地', [{ type: 'text', text: localPublicIpContent, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_MAIN, maxLines: 1 }], 10), // 第 2 行：本地
                    LeftRow('globe', C_ICON_IP, '落地', mProxyItems, 10), // 第 3 行：代理IP + DCH + 检测结果
                    LeftRow('number.square.fill', C_ICON_IP, '归属', [{ type: 'text', text: asnText, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN, maxLines: 1 }], 10), // 第 4 行：归属
                    LeftRow('mappin.and.ellipse', C_ICON_LO, '位置', [{ type: 'text', text: loc, font: { size: 10, weight: 'bold' }, textColor: C_MAIN, maxLines: 1 }], 10), // 第 5 行：位置
                    
                    // 第 6 行(灵活填充到底部)：分为左右两列显示解锁和多源评分
                    {
                        type: 'stack', direction: 'row', gap: 8, flex: 1, children: [
                            { type: 'stack', direction: 'column', gap: 2, flex: 1, children: unlocksAll },
                            { type: 'stack', direction: 'column', gap: 2, flex: 1, children: scoreRows },
                        ]
                    },
                ]
            };
        }

        // SystemSmall / Large 兼容适配 (确保其它尺寸不崩溃，同样采用左对齐)
        if (family === 'systemSmall') {
            return {
                type: 'widget', padding: 10, gap: 4, backgroundColor: BG_COLOR,
                children: [
                    {
                        type: 'stack', direction: 'row', alignItems: 'center', gap: 5, children: [
                            { type: 'image', src: 'sf-symbol:' + netIcon, color: C_TITLE, width: 13, height: 13 },
                            { type: 'text', text: currentISP, font: { size: 12, weight: 'heavy' }, textColor: C_TITLE, maxLines: 1 },
                            { type: 'spacer' },
                            { 
                                type: 'stack', direction: 'row', alignItems: 'center', gap: 2, children: [
                                    { type: 'image', src: 'sf-symbol:timer', color: C_SUB, width: 11, height: 11 },
                                    { type: 'text', text: refreshTimeStr, font: { size: 11, weight: 'regular' }, textColor: C_SUB }
                                ]
                            }
                        ]
                    },
                    LeftRow('location.circle.fill', C_BLUE, '本地', [{ type: 'text', text: localPublicIpContent, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_MAIN, maxLines: 1, minScale: 0.5 }], 10),
                    LeftRow('globe', C_ICON_IP, '落地', mProxyItems, 10),
                    LeftRow('number.square.fill', C_ICON_IP, '归属', [{ type: 'text', text: asnText.split(' ')[0], font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN, maxLines: 1, minScale: 0.5 }], 10),
                    LeftRow('mappin.and.ellipse', C_ICON_LO, '位置', [{ type: 'text', text: loc, font: { size: 10, weight: 'bold' }, textColor: C_MAIN, maxLines: 1, minScale: 0.5 }], 10),
                ]
            };
        }

        // systemLarge / ExtraLarge (其余尺寸兼容逻辑)
        var lgScoreRows = [];
        for (var i = 0; i < grades.length; i++) { lgScoreRows.push(ScoreRow(grades[i], 11)); }
        var lgUnlockRows = [
            UnlockRow('ChatGPT', uGPT, 11), UnlockRow('Gemini', uGemini, 11),
            UnlockRow('Netflix', uNetflix, 11), UnlockRow('TikTok', uTikTok, 11), UnlockRow('YouTube', uYouTube, 11)
        ];
        return {
            type: 'widget', padding: 14, gap: 8, backgroundColor: BG_COLOR,
            children: [
                {
                    type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                        { type: 'image', src: 'sf-symbol:' + netIcon, color: C_TITLE, width: 16, height: 16 },
                        { type: 'text', text: currentISP, font: { size: 15, weight: 'heavy' }, textColor: C_TITLE },
                        { type: 'spacer' },
                        { 
                            type: 'stack', direction: 'row', alignItems: 'center', gap: 2, children: [
                                { type: 'image', src: 'sf-symbol:timer', color: C_SUB, width: 14, height: 14 },
                                { type: 'text', text: refreshTimeStr, font: { size: 14, weight: 'regular' }, textColor: C_SUB }
                            ]
                        }
                    ]
                },
                LeftRow('location.circle.fill', C_BLUE, '本地公网', [{ type: 'text', text: localPublicIpContent, font: { size: 11, weight: 'bold', family: 'Menlo' }, textColor: C_MAIN }], 11),
                LeftRow('globe', C_ICON_IP, '落地 IP', mProxyItems, 11),
                LeftRow('number.square.fill', C_ICON_IP, '归属', [{ type: 'text', text: asnText, font: { size: 11, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN }], 11),
                LeftRow('mappin.and.ellipse', C_ICON_LO, '位置', [{ type: 'text', text: loc, font: { size: 11, weight: 'bold' }, textColor: C_MAIN }], 11),
                { type: 'stack', direction: 'row', backgroundColor: { light: '#E5E5EA', dark: '#38383A' }, height: 1 },
                {
                    type: 'stack', direction: 'row', gap: 10, flex: 1, children: [
                        { type: 'stack', direction: 'column', gap: 4, flex: 1, children: lgScoreRows },
                        { type: 'stack', direction: 'column', gap: 4, flex: 1, children: lgUnlockRows }
                    ]
                }
            ]
        };
    } catch (e) {
        return { type: 'widget', children: [{ type: 'text', text: '错误: ' + String(e) }] };
    }
}
