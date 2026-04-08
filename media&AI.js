/**
 * Egern 流媒体&AI解锁探测小组件
 */

export default async function (ctx) {
    // --- 1. 配置与颜色 ---
    const BG_COLOR = { light: '#FFFFFF', dark: '#1C1C1E' };
    const C_TITLE = { light: '#1A1A1A', dark: '#FFFFFF' };
    const C_SUB = { light: '#8E8E93', dark: '#8E8E93' };
    
    const C_GREEN = { light: '#34C759', dark: '#30D158' };
    const C_RED = { light: '#FF3B30', dark: '#FF453A' };
    const C_YELLOW = { light: '#FFCC00', dark: '#FFD60A' };

    const BRAND = {
        youtube: '#FF0000',
        netflix: '#E50914',
        disney: '#0063E5',
        chatgpt: { light: '#000000', dark: '#FFFFFF' },
        gemini: '#4285F4'
    };

    const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36';

    const baseHeaders = {
        'User-Agent': UA,
        'Connection': 'close',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    };
    
    const cb = `?t=${Date.now()}`;

    // --- 2. 核心检测函数 ---

    async function checkYouTube() {
        try {
            let res = await ctx.http.get('https://www.youtube.com/premium' + cb, { timeout: 4000, headers: baseHeaders });
            let data = await res.text();
            if (data.indexOf('Premium is not available') !== -1) return { status: 0 };
            let m = data.match(/"countryCode":"(.*?)"/);
            return { status: 2, region: m ? m[1].toUpperCase() : "US" };
        } catch (e) { return { status: 0 }; }
    }

    async function checkNetflix() {
        try {
            let res1 = await ctx.http.get('https://www.netflix.com/title/81280792' + cb, { timeout: 4000, headers: baseHeaders });
            if (res1.status === 200) {
                let region = (res1.headers['x-originating-url'] || "").split('/')[3]?.split('-')[0] || "US";
                return { status: 2, region: region.toUpperCase() === "TITLE" ? "US" : region.toUpperCase() };
            }
            let res2 = await ctx.http.get('https://www.netflix.com/title/80018499' + cb, { timeout: 4000, headers: baseHeaders });
            if (res2.status === 200) return { status: 1, region: "仅自制" };
        } catch (e) {}
        return { status: 0 };
    }

    async function checkDisney() {
        try {
            const body = {
                query: 'mutation registerDevice($input: RegisterDeviceInput!) { registerDevice(registerDevice: $input) { grant { grantType assertion } } }',
                variables: {
                    input: {
                        applicationRuntime: 'chrome',
                        attributes: {
                            browserName: 'chrome',
                            browserVersion: '94.0.4606',
                            manufacturer: 'apple',
                            model: null,
                            operatingSystem: 'macintosh',
                            operatingSystemVersion: '10.15.7',
                            osDeviceIds: [],
                        },
                        deviceFamily: 'browser',
                        deviceLanguage: 'en',
                        deviceProfile: 'macosx',
                    },
                },
            };
            let res = await ctx.http.post('https://disney.api.edge.bamgrid.com/graph/v1/device/graphql' + cb, {
                timeout: 4000,
                headers: {
                    ...baseHeaders,
                    'Accept-Language': 'en',
                    'Authorization': 'ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });
            let data = JSON.parse(await res.text());
            let sdk = data?.extensions?.sdk;
            if (sdk) {
                let { inSupportedLocation, location: { countryCode } } = sdk.session;
                if (inSupportedLocation === true || inSupportedLocation === 'true') {
                    return { status: 2, region: countryCode.toUpperCase() };
                } else {
                    return { status: 1, region: countryCode.toUpperCase() + " (Soon)" };
                }
            }
        } catch (e) {
            try {
                let res = await ctx.http.get('https://www.disneyplus.com/' + cb, { timeout: 4000, headers: baseHeaders });
                let m = (await res.text()).match(/Region: ([A-Z]{2})/);
                if (m) return { status: 2, region: m[1].toUpperCase() };
            } catch (e2) {}
        }
        return { status: 0 };
    }

    async function checkChatGPT() {
        try {
            let res = await ctx.http.get('https://ios.chat.openai.com/public-api/auth0/verify-device-registration-token' + cb, { timeout: 4000, headers: baseHeaders });
            if (res.status === 403 || res.status === 401) return { status: 0 };
            let traceRes = await ctx.http.get('https://chatgpt.com/cdn-cgi/trace' + cb, { timeout: 3000, headers: baseHeaders });
            let m = (await traceRes.text()).match(/loc=([A-Z]{2})/);
            return m ? { status: 2, region: m[1].toUpperCase() } : { status: 0 };
        } catch (e) { return { status: 0 }; }
    }

    async function checkGemini() {
        try {
            let res = await ctx.http.get('https://gemini.google.com/app' + cb, { timeout: 4000, headers: baseHeaders });
            let data = await res.text();
            if (data.indexOf('is not currently supported') !== -1 || data.indexOf('unavailable') !== -1) return { status: 0 };
            let m = data.match(/"countryCode":"([A-Z]{2})"/i) || data.match(/\\"([A-Z]{2})\\",\\"/);
            return { status: 2, region: m ? m[1].toUpperCase() : "OK" };
        } catch (e) { return { status: 0 }; }
    }

    // --- 3. UI 渲染辅助 ---

    function RenderRow(name, result, icon, brandColor) {
        let isOk = result.status === 2;
        let isWarn = result.status === 1;
        let textColor = isOk ? C_GREEN : (isWarn ? C_YELLOW : C_RED);
        let prefix = isOk ? "已解锁 ➟ " : "";
        let statusText = isOk ? `${prefix}${result.region || "OK"}` : (isWarn ? (name === 'Netflix' ? `已解锁 ➟ 仅自制` : `${result.region}`) : "❌ 不支持");

        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
            children: [
                { type: 'image', src: 'sf-symbol:' + icon, color: brandColor, width: 13, height: 13 },
                { type: 'text', text: name, font: { size: 12, weight: 'medium' }, textColor: C_TITLE, maxLines: 1 },
                { type: 'spacer' },
                { type: 'text', text: statusText, font: { size: 11, weight: 'bold', family: 'Menlo' }, textColor: textColor, maxLines: 1 }
            ]
        };
    }

    const [ytb, nflx, dsn, cgpt, gmn] = await Promise.all([
        checkYouTube(), checkNetflix(), checkDisney(), checkChatGPT(), checkGemini()
    ]);

    const timeStr = new Date().toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return {
        type: 'widget',
        padding: [14, 16, 14, 16],
        backgroundColor: BG_COLOR,
        gap: 10,
        children: [
            {
                type: 'stack', direction: 'row', alignItems: 'center',
                children: [
                    { type: 'text', text: '流媒体&AI解锁', font: { size: 14, weight: 'heavy' }, textColor: C_TITLE },
                    { type: 'spacer' },
                    { type: 'text', text: timeStr, font: { size: 9, family: 'Menlo' }, textColor: C_SUB }
                ]
            },
            { type: 'stack', direction: 'row', backgroundColor: { light: '#EEE', dark: '#333' }, height: 1 },
            {
                type: 'stack', direction: 'column', gap: 8,
                children: [
                    RenderRow('YouTube', ytb, 'play.rectangle.fill', BRAND.youtube),
                    RenderRow('Netflix', nflx, 'n.square.fill', BRAND.netflix),
                    RenderRow('Disney+', dsn, 'play.tv.fill', BRAND.disney),
                    RenderRow('ChatGPT', cgpt, 'camera.macro.circle.fill', BRAND.chatgpt),
                    RenderRow('Gemini', gmn, 'g.circle.fill', BRAND.gemini)
                ]
            }
        ]
    };
}
