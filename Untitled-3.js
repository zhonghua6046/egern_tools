/**
 * IP multi-source purity check widget + Streaming/AI unlock detection
 * Sources: IPPure / ipapi.is / IP2Location / Scamalytics / DB-IP / ipinfo
 * Unlock: ChatGPT / Gemini / Netflix / YouTube Premium / Netflix / Disney+ / TikTok
 * Env: POLICY, MARK_IP
 * Layout: Custom Left-Aligned Order + Compact fit
 */
export default async function (ctx) {
    var BG_COLOR = { light: '#FFFFFF', dark: '#1C1C1E' };
    var C_TITLE = { light: '#1A1A1A', dark: '#FFD700' };
    var C_SUB = { light: '#666666', dark: '#B0B0B0' }; 
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

    var BASE_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36";
    var cb = "?t=" + Date.now();

    var reqHeaders = {
        'User-Agent': BASE_UA,
        'Connection': 'close',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    };

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
    
    async function postRaw(url, body, headers, extraOpts) {
        var opts = { timeout: 10000, body: body };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        if (extraOpts) { for (var k in extraOpts) opts[k] = extraOpts[k]; }
        return await ctx.http.post(url, opts);
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

    function gradeIppure(score) {
        var s = ti(score); if (s === null) return null;
        if (s >= 80) return { sev: 4, t: 'IPPure: \u6781\u9AD8 (' + s + ')' };
        if (s >= 70) return { sev: 3, t: 'IPPure: \u9AD8\u5371 (' + s + ')' };
        if (s >= 40) return { sev: 1, t: 'IPPure: \u4E2D\u7B49 (' + s + ')' };
        return { sev: 0, t: 'IPPure: \u4F4E\u5371 (' + s + ')' };
    }

    function gradeIpapi(j) {
        if (!j) return null;
        if (!j.company || !j.company.abuser_score) return null;
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

    function gradeDbip(data) {
        if (!data) return null;
        var lv = '';
        if (typeof data === 'string') {
            var m = data.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
            lv = (m ? m[1] : '').toLowerCase();
        } else {
            lv = String(data.threatLevel || data.threat_level || '').toLowerCase();
        }
        if (lv === 'high') return { sev: 3, t: 'DB-IP: \u9AD8\u5371' };
        if (lv === 'medium') return { sev: 1, t: 'DB-IP: \u4E2D\u5371' };
        if (lv === 'low') return { sev: 0, t: 'DB-IP: \u4F4E\u5371' };
        return null;
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

    async function fetchIpapi(ip) {
        if (!ip) return null;
        return jp(await get('https://api.ipapi.is/?q=' + encodeURIComponent(ip)));
    }

    async function fetchDbip(ip) {
        if (!ip) return null;
        return jp(await get('http://api.db-ip.com/v2/free/' + encodeURIComponent(ip)));
    }

    async function fetchScam(ip) {
        return await get('https://scamalytics.com/ip/' + encodeURIComponent(ip));
    }

    async function fetchIp2loc(ip) {
        if (!ip) return null;
        var data = jp(await get('https://api.ip2location.io/?ip=' + encodeURIComponent(ip) + '&format=json'));
        if (data) {
            return {
                countryCode: data.country_code || null,
                countryName: data.country_name || null,
                cityName: data.city_name || null,
                usageType: data.usage_type || data.usageType || null,
                fraudScore: data.fraud_score !== undefined ? ti(data.fraud_score) : (data.fraudScore !== undefined ? ti(data.fraudScore) : null),
                asn: data.asn || null,
                as: data.as || null,
                isp: data.isp || null
            };
        }
        return null;
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

    async function checkYouTube() {
        try {
            var res = await getRaw('https://www.youtube.com/premium' + cb, reqHeaders);
            if (!res) return "\u274C";
            var data = await res.text();
            if (data.indexOf('Premium is not available') !== -1 || data.indexOf('YouTube Premium is not available') !== -1) return "\u274C";
            if (data.indexOf('www.google.cn') !== -1) return "CN";
            var m = data.match(/"countryCode":"(.*?)"/);
            var reg = (m && m[1]) ? m[1].toUpperCase() : "US";
            if (reg.length > 3 || reg === "OK") reg = "US";
            return reg;
        } catch (e) { return "\u274C"; }
    }

    async function checkNetflix() {
        try {
            var res1 = await getRaw('https://www.netflix.com/title/81280792' + cb, reqHeaders);
            if (res1 && (res1.status === 200 || res1.status === 301 || res1.status === 302)) {
                var headers = res1.headers || {};
                var origUrl = headers['x-originating-url'] || headers['X-Originating-Url'] || "";
                var parts = origUrl.split('/');
                var region = (parts.length > 3) ? parts[3].split('-')[0] : "US";
                if (region.toUpperCase() === "TITLE" || region === "") region = "US";
                return region.toUpperCase();
            }
            var res2 = await getRaw('https://www.netflix.com/title/80018499' + cb, reqHeaders);
            if (res2 && res2.status === 200) return "\u4EC5\u81EA\u5236";
        } catch (e) {}
        return "\u274C";
    }
    async function checkDisney() {
        try {
            var body = {
                query: 'mutation registerDevice($input: RegisterDeviceInput!) { registerDevice(registerDevice: $input) { grant { grantType assertion } } }',
                variables: {
                    input: {
                        applicationRuntime: 'chrome',
                        attributes: { browserName: 'chrome', browserVersion: '94.0.4606', manufacturer: 'apple', model: null, operatingSystem: 'macintosh', operatingSystemVersion: '10.15.7', osDeviceIds: [] },
                        deviceFamily: 'browser', deviceLanguage: 'en', deviceProfile: 'macosx'
                    }
                }
            };
            var authHeaders = Object.assign({}, reqHeaders, {
                'Accept-Language': 'en',
                'Authorization': 'ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84',
                'Content-Type': 'application/json'
            });
            var res = await postRaw('https://disney.api.edge.bamgrid.com/graph/v1/device/graphql' + cb, JSON.stringify(body), authHeaders);
            if (res) {
                var text = await res.text();
                var data = JSON.parse(text);
                var sdk = data && data.extensions && data.extensions.sdk;
                if (sdk) {
                    var inLoc = sdk.session.inSupportedLocation;
                    var cc = sdk.session.location.countryCode;
                    if (inLoc === true || inLoc === 'true') {
                        return cc.toUpperCase();
                    } else {
                        return cc.toUpperCase() + " (Soon)";
                    }
                }
            }
        } catch (e) {
            try {
                var res2 = await getRaw('https://www.disneyplus.com/' + cb, reqHeaders);
                var text2 = res2 ? await res2.text() : "";
                var m = text2.match(/Region: ([A-Z]{2})/);
                if (m) return m[1].toUpperCase();
            } catch (e2) {}
        }
        return "\u274C";
    }

    async function checkChatGPT() {
        try {
            var res = await getRaw('https://ios.chat.openai.com/public-api/auth0/verify-device-registration-token' + cb, reqHeaders);
            if (res && (res.status === 403 || res.status === 401)) return "\u274C";
            var traceRes = await getRaw('https://chatgpt.com/cdn-cgi/trace' + cb, reqHeaders);
            if (traceRes) {
                var text = await traceRes.text();
                var m = text.match(/loc=([A-Z]{2})/);
                if (m) return m[1].toUpperCase();
            }
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    async function checkGemini() {
        try {
            var res = await getRaw('https://gemini.google.com/app' + cb, reqHeaders);
            var data = res ? await res.text() : "";
            if (data.indexOf('is not currently supported') !== -1 || data.indexOf('unavailable') !== -1) return "\u274C";
            var m = data.match(/"countryCode":"([A-Z]{2})"/i) || data.match(/\\"([A-Z]{2})\\",\\"/);
            return m ? m[1].toUpperCase() : "OK";
        } catch (e) { return "\u274C"; }
    }
    
    async function checkClaude() {
        try {
            var res = await getRaw("https://claude.ai/login", reqHeaders);
            if (!res) return "\u274C";
            var status = res.status;
            var body = await res.text();
            if (body.indexOf("App unavailable") !== -1 || body.indexOf("certain regions") !== -1) return "\u274C";
            if (status === 403 && body.indexOf("1020") !== -1) return "\u274C";
            if (status === 200 || status === 301 || status === 302 || (status === 403 && (body.indexOf("cf-turnstile") !== -1 || body.indexOf("Just a moment") !== -1 || body.indexOf("Challenge") !== -1))) {
                var traceRes = await getRaw('https://claude.ai/cdn-cgi/trace' + cb, reqHeaders);
                if (traceRes) {
                    var traceTxt = await traceRes.text();
                    var m = traceTxt.match(/loc=([A-Z]{2})/);
                    if (m && m[1]) return m[1].toUpperCase();
                }
                return "OK";
            }
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }
    
    async function checkTikTok() {
        try {
            var body = await get("https://www.tiktok.com/" + cb, reqHeaders);
            if (body && (body.indexOf("Please wait...") !== -1 || body.indexOf("Access Denied") !== -1)) {
                body = await get("https://www.tiktok.com/@tiktok" + cb, reqHeaders) || body;
            }
            if (!body) return "\u274C";
            
            var m = body.match(/"region"\s*:\s*"([A-Za-z]{2})"/i) || 
                    body.match(/"sys_region"\s*:\s*"([A-Za-z]{2})"/i) || 
                    body.match(/"location"\s*:\s*"([A-Za-z]{2})"/i) || 
                    body.match(/"country"\s*:\s*"([A-Za-z]{2})"/i) || 
                    body.match(/"countryCode"\s*:\s*"([A-Za-z]{2})"/i);
                    
            if (m && m[1]) return m[1].toUpperCase();

            var mUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";
            var bodyMob = await get("https://www.tiktok.com/" + cb, Object.assign({}, reqHeaders, { "User-Agent": mUA }));
            if (bodyMob) {
                var mMob = bodyMob.match(/"region"\s*:\s*"([A-Za-z]{2})"/i) || 
                           bodyMob.match(/"sys_region"\s*:\s*"([A-Za-z]{2})"/i) || 
                           bodyMob.match(/"country"\s*:\s*"([A-Za-z]{2})"/i);
                if (mMob && mMob[1]) return mMob[1].toUpperCase();
            }

            if (body.indexOf('tiktok') !== -1 || (bodyMob && bodyMob.indexOf('tiktok') !== -1)) return "OK";
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    function LeftRow(iconName, iconColor, label, items, fontSize) {
        var fz = fontSize || 10;
        var children = [
            { type: 'image', src: 'sf-symbol:' + iconName, color: iconColor, width: fz+1, height: fz+1 },
            { type: 'text', text: label, font: { size: fz }, textColor: C_SUB }
        ];
        for (var i = 0; i < items.length; i++) {
            children.push(items[i]);
        }
        children.push({ type: 'spacer' });
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
            children: children
        };
    }

    function ScoreRow(grade, fz) {
        var sz = fz || 9;
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
                { type: 'text', text: val, font: { size: sz, weight: 'bold', family: 'Menlo' }, textColor: col, maxLines: 1, minScale: 0.5 }
            ]
        };
    }

    function UnlockRow(name, result, fz) {
        var sz = fz || 9;
        var isFail = result === "\u274C" || result === "CN";
        var isWarn = result === "\uD83C\uDF7F" || result === "\u23F3" || result === "APP" || result.indexOf("\u4EC5\u81EA\u5236") !== -1 || result.indexOf("Soon") !== -1;
        var isOk = !isFail && !isWarn;
        
        var color = isOk ? C_GREEN : (isWarn ? C_YELLOW : C_RED);
        var icon = isOk ? 'checkmark.circle.fill' : (isWarn ? 'exclamationmark.circle.fill' : 'xmark.circle.fill');
        
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 3,
            children: [
                { type: 'image', src: 'sf-symbol:' + icon, color: color, width: sz, height: sz },
                { type: 'text', text: name, font: { size: sz }, textColor: C_SUB },
                { type: 'spacer' },
                { type: 'text', text: result, font: { size: sz, weight: 'bold' }, textColor: color, maxLines: 1 }
            ]
        };
    }
        try {
        var ip = null, cachedIpapi = null;
        try {
            var d_ip = jp(await get('http://ip-api.com/json?lang=zh-CN'));
            ip = d_ip && (d_ip.query || d_ip.ip);
        } catch (e) { }
        if (!ip) {
            try { 
                var tempIpapi = jp(await get('https://api.ipapi.is/')); 
                ip = tempIpapi && tempIpapi.ip; 
            } catch (e) { }
        }
        if (!ip) return { type: 'widget', children: [{ type: 'text', text: '获取 IP 失败' }] };

        var ippureScore = null;
        try { 
            var d2 = jp(await get('https://my.ippure.com/v1/info')); 
            ippureScore = d2 && (
                d2.fraudScore !== undefined 
                    ? d2.fraudScore 
                    : (
                        d2.fraud_score !== undefined 
                            ? d2.fraud_score 
                            : d2.score
                    )
            ); 
        } catch (e) { }

        var results = await Promise.all([
            safe(function () { return fetchIpapi(ip); }),
            safe(function () { return fetchIp2loc(ip); }),
            safe(function () { return fetchIpinfo(ip); }),
            safe(function () { return fetchDbip(ip); }),
            safe(function () { return fetchScam(ip); }),
            safe(checkChatGPT),
            safe(checkGemini),
            safe(checkNetflix),
            safe(checkTikTok),
            safe(checkYouTube),
            safe(checkDisney),          
            safe(checkClaude),
            safe(fetchLocalPublicIP)    
        ]);

        var rIpapi = results[0], rIp2loc = results[1], rIpinfo = results[2];
        var rDbip = results[3], rScam = results[4];
        var uGPT = results[5] || "\u274C", uGemini = results[6] || "\u274C";
        var uNetflix = results[7] || "\u274C", uTikTok = results[8] || "\u274C";
        var uYouTube = results[9] || "\u274C";
        var uDisney = results[10] || "\u274C";
        var uClaude = results[11] || "\u274C";
        var localIpData = results[12] || {};

        /*
         * ipapi.is 兼容新旧返回格式
         *
         * 旧格式：
         *   asn.asn
         *   asn.org
         *   location.country_code
         *   location.country
         *   location.city
         *
         * 新格式：
         *   asn_num
         *   asn_org
         *   cc
         *   country
         *   city
         */
        var ipapiD = rIpapi || {};

        var asnNum =
            ipapiD.asn_num ||
            ipapiD.asn_number ||
            (
                ipapiD.asn &&
                ipapiD.asn.asn
            ) ||
            null;

        var asnOrg =
            ipapiD.asn_org ||
            ipapiD.asn_name ||
            (
                ipapiD.asn &&
                ipapiD.asn.org
            ) ||
            ipapiD.org ||
            ipapiD.organization ||
            "";

        /*
         * 如果 ipapi.is 没有 ASN，
         * 尝试从 IP2Location / DB-IP 补充
         */
        if (!asnNum && rIp2loc) {
            asnNum =
                rIp2loc.asn ||
                rIp2loc.asn_num ||
                rIp2loc.asn_number ||
                null;
        }

        if (!asnOrg && rIp2loc) {
            asnOrg =
                rIp2loc.isp ||
                rIp2loc.asn_org ||
                "";
        }

        if (!asnNum && rDbip && typeof rDbip === 'object') {
            asnNum =
                rDbip.asn ||
                rDbip.asnNumber ||
                null;
        }

        if (!asnOrg && rDbip && typeof rDbip === 'object') {
            asnOrg =
                rDbip.organization ||
                rDbip.org ||
                rDbip.asnOrganization ||
                "";
        }

        var asnText = asnNum
            ? (
                'AS' +
                String(asnNum).replace(/^AS/i, '') +
                (asnOrg ? ' ' + asnOrg : '')
            ).trim()
            : '\u672A\u77E5';

        var location =
            (
                ipapiD.location &&
                typeof ipapiD.location === 'object'
            )
                ? ipapiD.location
                : {};

        var cc =
            ipapiD.cc ||
            ipapiD.country_code ||
            ipapiD.countryCode ||
            location.country_code ||
            location.countryCode ||
            "";

        var country =
            ipapiD.country ||
            ipapiD.country_name ||
            location.country ||
            location.country_name ||
            "";

        var city =
            ipapiD.city ||
            ipapiD.city_name ||
            location.city ||
            location.city_name ||
            "";

        /*
         * IP2Location 作为位置备用
         */
        if (!cc && rIp2loc) {
            cc =
                rIp2loc.countryCode ||
                rIp2loc.country_code ||
                rIp2loc.countryShort ||
                "";
        }

        if (!country && rIp2loc) {
            country =
                rIp2loc.countryName ||
                rIp2loc.country_name ||
                "";
        }

        if (!city && rIp2loc) {
            city =
                rIp2loc.cityName ||
                rIp2loc.city_name ||
                "";
        }

        /*
         * DB-IP 作为第二备用位置
         */
        if (rDbip && typeof rDbip === 'object') {
            if (!cc) {
                cc =
                    rDbip.countryCode ||
                    rDbip.country_code ||
                    (
                        rDbip.country &&
                        (
                            rDbip.country.code ||
                            rDbip.countryCode
                        )
                    ) ||
                    "";
            }

            if (!country) {
                country =
                    rDbip.countryName ||
                    rDbip.country_name ||
                    (
                        rDbip.country &&
                        (
                            rDbip.country.name ||
                            rDbip.countryName
                        )
                    ) ||
                    "";
            }

            if (!city) {
                city =
                    rDbip.city ||
                    rDbip.cityName ||
                    (
                        rDbip.location &&
                        (
                            rDbip.location.city ||
                            rDbip.location.cityName
                        )
                    ) ||
                    "";
            }
        }

        var loc = (
            toFlag(cc) +
            ' ' +
            country +
            ' ' +
            city
        ).trim();

        if (!cc && !country && !city) {
            loc = '\u672A\u77E5\u4F4D\u7F6E';
        }

        /*
         * IP2Location 使用类型
         */
        var ip2Usage =
            rIp2loc &&
            (
                rIp2loc.usageType ||
                rIp2loc.usage_type ||
                rIp2loc.usage ||
                null
            );

        var hosting = usageText(ip2Usage);

        /*
         * IP2Location Fraud Score
         */
        var ip2FraudScore =
            rIp2loc &&
            (
                rIp2loc.fraudScore !== undefined
                    ? rIp2loc.fraudScore
                    : (
                        rIp2loc.fraud_score !== undefined
                            ? rIp2loc.fraud_score
                            : null
                    )
            );

        var d_ctx = ctx.device || {};
        var wifiSsid = (d_ctx.wifi && d_ctx.wifi.ssid) ? d_ctx.wifi.ssid : "";
        var cellularRadio = (d_ctx.cellular && d_ctx.cellular.radio) ? d_ctx.cellular.radio : "";
        
        var rawISP =
            (
                Array.isArray(localIpData.location)
                    ? localIpData.location[localIpData.location.length - 1]
                    : ""
            ) ||
            asnOrg ||
            ipapiD.asn_org ||
            ipapiD.org ||
            "";

        var currentISP = wifiSsid;

        if (!wifiSsid) {
            var fullISP = fmtISP(rawISP);
            var shortISP = fullISP.replace("中国", ""); 
            
            if (cellularRadio) {
                var map = { GPRS:"2G", EDGE:"2G", LTE:"4G", "LTE-CA":"4G+", NR:"5G" };
                var gen = map[cellularRadio] || cellularRadio;
                currentISP = shortISP + " " + gen;
            } else {
                currentISP = shortISP;
            }
        }
        
        var netIcon = wifiSsid ? 'wifi' : (cellularRadio ? 'antenna.radiowaves.left.and.right' : 'wifi.slash');

        var locStr = "";
        var localISPName = "";

        if (Array.isArray(localIpData.location)) {
            var validLocs = localIpData.location.filter(Boolean);

            if (validLocs.length > 0) {
                var lastLoc = validLocs[validLocs.length - 1];

                if (/\u7535\u4FE1|\u79FB\u52A8|\u8054\u901A|\u5E7F\u7535/i.test(lastLoc)) {
                    localISPName = fmtISP(lastLoc);
                }
            }

            var tags = localIpData.location.filter(function(i) {
                return i && !/\u7535\u4FE1|\u79FB\u52A8|\u8054\u901A|\u5E7F\u7535|IP|China|\u4E2D\u56FD|\u6570\u636E\u4E2D\u5FC3/i.test(i);
            });

            var uniqueTags = [];

            for (var i=0; i<tags.length; i++) {
                if (uniqueTags.indexOf(tags[i]) === -1) {
                    uniqueTags.push(tags[i]);
                }
            }

            if (uniqueTags.length >= 2) {
                locStr =
                    uniqueTags[uniqueTags.length - 2] +
                    " - " +
                    uniqueTags[uniqueTags.length - 1];
            } else if (uniqueTags.length === 1) {
                locStr = uniqueTags[0];
            }
        }

        var localPublicIpContent =
            [
                localIpData.ip || "\u672A\u83B7\u53D6",
                locStr,
                localISPName
            ]
            .filter(Boolean)
            .join(" - ");

        var nowObj = new Date();
        var timeH = nowObj.getHours().toString().padStart(2, '0');
        var timeM = nowObj.getMinutes().toString().padStart(2, '0');
        var timeS = nowObj.getSeconds().toString().padStart(2, '0');
        var refreshTimeStr = timeH + ':' + timeM + ':' + timeS;

        var grades = [
            gradeIppure(ippureScore),
            gradeIpapi(rIpapi),
            gradeIp2loc(ip2FraudScore),
            gradeScam(rScam),
            gradeDbip(rDbip)
        ].filter(Boolean);

        var maxSev = 0;

        for (var i = 0; i < grades.length; i++) {
            if (grades[i].sev > maxSev) maxSev = grades[i].sev;
        }

        var showIP = markIP ? maskIP(ip) : ip;

        var mProxyItems = [
            {
                type: 'text',
                text: showIP,
                font: {
                    size: 10,
                    weight: 'bold',
                    family: 'Menlo'
                },
                textColor: C_GREEN,
                maxLines: 1,
                minScale: 0.8
            }
        ];

        if (hosting) {
            mProxyItems.push({
                type: 'text',
                text: '| ' + hosting,
                font: {
                    size: 9,
                    weight: 'bold'
                },
                textColor: C_SUB,
                maxLines: 1,
                minScale: 0.8
            });
        }

        mProxyItems.push({
            type: 'image',
            src: 'sf-symbol:' + sevIcon(maxSev),
            color: sevColor(maxSev),
            width: 9,
            height: 9
        });

        mProxyItems.push({
            type: 'text',
            text: sevText(maxSev),
            font: {
                size: 9,
                weight: 'bold'
            },
            textColor: sevColor(maxSev),
            maxLines: 1,
            minScale: 0.8
        });

        var family = ctx.widgetFamily || 'systemMedium';
                if (family === 'systemMedium') {
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

            var unlocksAll = [
                UnlockRow('YouTube', uYouTube, 9),
                UnlockRow('Netflix', uNetflix, 9),
                UnlockRow('Disney+', uDisney, 9),
                UnlockRow('ChatGPT', uGPT, 9),
                UnlockRow('Gemini', uGemini, 9),
                UnlockRow('Claude', uClaude, 9)
            ];

            var scoreRows = [];
            for (var i = 0; i < grades.length; i++) {
                scoreRows.push(ScoreRow(grades[i], 9));
            }
            scoreRows.push(UnlockRow('TikTok', uTikTok, 9));

            return {
                type: 'widget', padding: [6, 12, 6, 12], gap: 2, backgroundColor: BG_COLOR,
                children: [
                    row1Network, 
                    LeftRow('location.circle.fill', C_BLUE, '本地', [{ type: 'text', text: localPublicIpContent, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_MAIN, maxLines: 1 }], 10),
                    LeftRow('globe', C_ICON_IP, '落地', mProxyItems, 10), 
                    LeftRow('number.square.fill', C_ICON_IP, '归属', [{ type: 'text', text: asnText, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN, maxLines: 1 }], 10), 
                    LeftRow('mappin.and.ellipse', C_ICON_LO, '位置', [{ type: 'text', text: loc, font: { size: 10, weight: 'bold' }, textColor: C_MAIN, maxLines: 1 }], 10),
                    { type: 'spacer', length: 2 },
                    {
                        type: 'stack', direction: 'row', gap: 8, flex: 1, children: [
                            { type: 'stack', direction: 'column', gap: 2, flex: 1, children: unlocksAll },
                            { type: 'stack', direction: 'column', gap: 2, flex: 1, children: scoreRows },
                        ]
                    },
                ]
            };
        }

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

        var lgScoreRows = [];
        for (var i = 0; i < grades.length; i++) { lgScoreRows.push(ScoreRow(grades[i], 11)); }
        lgScoreRows.push(UnlockRow('TikTok', uTikTok, 11));
        
        var lgUnlockRows = [
            UnlockRow('YouTube', uYouTube, 11), 
            UnlockRow('Netflix', uNetflix, 11), 
            UnlockRow('Disney+', uDisney, 11),
            UnlockRow('ChatGPT', uGPT, 11), 
            UnlockRow('Gemini', uGemini, 11),
            UnlockRow('Claude', uClaude, 11)
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
                        { type: 'stack', direction: 'column', gap: 4, flex: 1, children: lgUnlockRows },
                        { type: 'stack', direction: 'column', gap: 4, flex: 1, children: lgScoreRows }
                    ]
                }
            ]
        };
    } catch (e) {
        return { type: 'widget', children: [{ type: 'text', text: '错误: ' + String(e) }] };
    }
}