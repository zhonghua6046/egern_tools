/**
 * 网络状态小组件 — 流媒体分流解锁检测 + IP 风险评估
 * 前提: Egern 已配置好各服务对应的分流规则
 * 适配尺寸: iOS systemMedium / systemLarge
 */

export default async function(ctx) {
  const widgetFamily = ctx.widgetFamily || 'systemMedium';

  const BG_COLOR = { light: '#FFFFFF', dark: '#1C1C1E' };
  const C_TITLE = { light: '#000000', dark: '#FFFFFF' };
  const C_SUB = { light: '#666666', dark: '#8E8E93' };
  const C_MAIN = { light: '#000000', dark: '#FFFFFF' };
  const C_GREEN = { light: '#32D74B', dark: '#32D74B' };
  const C_YELLOW = { light: '#FF9500', dark: '#FF9500' };
  const C_ORANGE = { light: '#FF9500', dark: '#FF9500' };
  const C_RED = { light: '#FF3B30', dark: '#FF3B30' };
  const C_ICON = { light: '#007AFF', dark: '#0A84FF' };

  if ([
    'systemSmall',
    'accessoryCircular',
    'accessoryInline',
    'accessoryRectangular'
  ].includes(widgetFamily)) {
    return {
      type: 'widget',
      padding: 16,
      backgroundColor: BG_COLOR,
      children: [{
        type: 'text',
        text: '请使用中号或大号组件',
        font: { size: 'callout' },
        textColor: C_MAIN,
        textAlign: 'center'
      }]
    };
  }

  // 仅用于顶部「落地 IP」查询；所有解锁检测均不传 policy，严格走 Egern 分流规则
  const BASE_POLICY = String(ctx.env.POLICY || '').trim();

  const BASE_UA =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
  const DESKTOP_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
  const GOOGLE_CONSENT_COOKIE = 'CONSENT=YES+cb.20210328-17-p0.en+FX+667';

  const ISO3_MAP = {
    HKG: 'HK', MAC: 'MO', TWN: 'TW', CHN: 'CN',
    SGP: 'SG', JPN: 'JP', KOR: 'KR', USA: 'US',
    GBR: 'GB', DEU: 'DE', FRA: 'FR', NLD: 'NL',
    CAN: 'CA', AUS: 'AU', MYS: 'MY', THA: 'TH',
    IND: 'IN', IDN: 'ID', PHL: 'PH', VNM: 'VN',
    RUS: 'RU', TUR: 'TR', ARG: 'AR', BRA: 'BR',
    MEX: 'MX', ESP: 'ES', ITA: 'IT', CHE: 'CH',
    SWE: 'SE', NOR: 'NO', FIN: 'FI', DNK: 'DK',
    POL: 'PL', AUT: 'AT', BEL: 'BE', IRL: 'IE',
    NZL: 'NZ', ZAF: 'ZA', ARE: 'AE', SAU: 'SA',
    ISR: 'IL', UKR: 'UA', ROU: 'RO', BGR: 'BG',
    CZE: 'CZ', HUN: 'HU', GRC: 'GR', PRT: 'PT',
    LUX: 'LU', ISL: 'IS', PAK: 'PK', BGD: 'BD',
    LKA: 'LK', NPL: 'NP', KAZ: 'KZ', UZB: 'UZ',
    CHL: 'CL', COL: 'CO', PER: 'PE', EGY: 'EG',
    NGA: 'NG', KEN: 'KE', BLR: 'BY', IRN: 'IR',
    PRK: 'KP', CUB: 'CU', SYR: 'SY', SDN: 'SD'
  };

  // Google K4WWud 返回的英文国家/地区名映射
  const COUNTRY_NAME_MAP = [
    [/\btaiwan\b/i, 'TW'],
    [/\bhong kong\b/i, 'HK'],
    [/\bmacao\b|\bmacau\b/i, 'MO'],
    [/\bchina\b/i, 'CN'],
    [/\bsingapore\b/i, 'SG'],
    [/\bjapan\b/i, 'JP'],
    [/\bsouth korea\b|\brepublic of korea\b|\bkorea\b/i, 'KR'],
    [/\bunited states\b|\busa\b/i, 'US'],
    [/\bunited kingdom\b|\bgreat britain\b|\bengland\b|\bscotland\b|\bwales\b|\buk\b/i, 'GB'],
    [/\bgermany\b/i, 'DE'],
    [/\bfrance\b/i, 'FR'],
    [/\bnetherlands\b/i, 'NL'],
    [/\bcanada\b/i, 'CA'],
    [/\baustralia\b/i, 'AU'],
    [/\bmalaysia\b/i, 'MY'],
    [/\bthailand\b/i, 'TH'],
    [/\bindia\b/i, 'IN'],
    [/\bindonesia\b/i, 'ID'],
    [/\bphilippines\b/i, 'PH'],
    [/\bvietnam\b|\bviet nam\b/i, 'VN'],
    [/\brussia\b/i, 'RU'],
    [/\bturkey\b|\btürkiye\b/i, 'TR'],
    [/\bargentina\b/i, 'AR'],
    [/\bbrazil\b/i, 'BR'],
    [/\bmexico\b/i, 'MX'],
    [/\bspain\b/i, 'ES'],
    [/\bitaly\b/i, 'IT'],
    [/\bswitzerland\b/i, 'CH'],
    [/\bsweden\b/i, 'SE'],
    [/\bnorway\b/i, 'NO'],
    [/\bfinland\b/i, 'FI'],
    [/\bdenmark\b/i, 'DK'],
    [/\bpoland\b/i, 'PL'],
    [/\baustria\b/i, 'AT'],
    [/\bbelgium\b/i, 'BE'],
    [/\bireland\b/i, 'IE'],
    [/\bnew zealand\b/i, 'NZ'],
    [/\bsouth africa\b/i, 'ZA'],
    [/\bunited arab emirates\b|\buae\b/i, 'AE'],
    [/\bsaudi arabia\b/i, 'SA'],
    [/\bisrael\b/i, 'IL'],
    [/\bukraine\b/i, 'UA'],
    [/\bromania\b/i, 'RO'],
    [/\bbulgaria\b/i, 'BG'],
    [/\bczechia\b|\bczech republic\b/i, 'CZ'],
    [/\bhungary\b/i, 'HU'],
    [/\bgreece\b/i, 'GR'],
    [/\bportugal\b/i, 'PT'],
    [/\bluxembourg\b/i, 'LU'],
    [/\biceland\b/i, 'IS'],
    [/\bpakistan\b/i, 'PK'],
    [/\bbangladesh\b/i, 'BD'],
    [/\bsri lanka\b/i, 'LK'],
    [/\bnepal\b/i, 'NP'],
    [/\bkazakhstan\b/i, 'KZ'],
    [/\buzbekistan\b/i, 'UZ'],
    [/\bchile\b/i, 'CL'],
    [/\bcolombia\b/i, 'CO'],
    [/\bperu\b/i, 'PE'],
    [/\begypt\b/i, 'EG'],
    [/\bnigeria\b/i, 'NG'],
    [/\bkenya\b/i, 'KE'],
    [/\bbelarus\b/i, 'BY'],
    [/\biran\b/i, 'IR'],
    [/\bnorth korea\b/i, 'KP'],
    [/\bcuba\b/i, 'CU'],
    [/\bsyria\b/i, 'SY'],
    [/\bsudan\b/i, 'SD']
  ];

  function toAlpha2(code) {
    if (!code) return null;
    const c = String(code).trim().toUpperCase();
    if (c.length === 3 && ISO3_MAP[c]) return ISO3_MAP[c];
    if (c.length === 2 && /^[A-Z]{2}$/.test(c)) return c;
    return null;
  }

  function locationNameToAlpha2(locStr) {
    if (!locStr) return null;
    const s = String(locStr).trim();
    for (const [re, code] of COUNTRY_NAME_MAP) {
      if (re.test(s)) return code;
    }
    const tail = s.split(',').pop()?.trim();
    return toAlpha2(tail);
  }

  // 通用分流请求：不指定 policy，完全交由 Egern 分流规则路由
  async function routeGet(url, headers, extraOpts) {
    const opts = { timeout: 6000 };
    if (headers) opts.headers = headers;
    if (extraOpts) Object.assign(opts, extraOpts);
    const res = await ctx.http.get(url, opts);
    return await res.text();
  }

  async function routePost(url, body, headers, extraOpts) {
    const opts = { timeout: 6000, body };
    if (headers) opts.headers = headers;
    if (extraOpts) Object.assign(opts, extraOpts);
    const res = await ctx.http.post(url, opts);
    return await res.text();
  }

  function directOpts(timeout) {
    return { timeout, policy: 'DIRECT' };
  }

  function proxyOpts(timeout) {
    const opts = { timeout };
    if (BASE_POLICY && BASE_POLICY !== 'DIRECT') {
      opts.policy = BASE_POLICY;
    }
    return opts;
  }

  function jp(v) {
    try {
      return JSON.parse(v);
    } catch (e) {
      return null;
    }
  }

  function ti(v) {
    const n = Number(v);
    return Number.isFinite(n) ? Math.round(n) : null;
  }

  function isIPv4(ip) {
    return /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(ip);
  }

  function fmtISP(isp) {
    if (!isp) return '';
    const s = String(isp).toLowerCase();
    if (/移动|mobile|cmcc/i.test(s)) return '中国移动';
    if (/电信|telecom|chinanet/i.test(s)) return '中国电信';
    if (/联通|unicom/i.test(s)) return '中国联通';
    if (/广电|broadcast|cbn/i.test(s)) return '中国广电';
    return isp;
  }

  // ============================================================
  // 1. 本地直连探测
  // ============================================================

  let lIp = '获取失败';
  let lLoc = '未知位置';
  let lIsp = '';

  try {
    const resV4 = await ctx.http.get('http://4.ipw.cn/api/ip/myip?json=true', directOpts(2500));
    const dataV4 = jp(await resV4.text());
    if (dataV4 && isIPv4(dataV4.IP)) lIp = dataV4.IP;
  } catch (e) {}

  try {
    const lRes = await ctx.http.get('https://myip.ipip.net/json', {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      ...directOpts(3000)
    });
    const body = jp(await lRes.text());
    if (body?.data) {
      if (lIp === '获取失败' && isIPv4(body.data.ip)) lIp = body.data.ip;
      const locArr = body.data.location || [];
      lLoc = `${locArr[1] || ''} ${locArr[2] || ''}`.trim() || '未知位置';
      lIsp = fmtISP(locArr[4] || locArr[3]);
    }
  } catch (e) {}

  if (lIp === '获取失败' || lLoc === '未知位置') {
    try {
      const res126 = await ctx.http.get('https://ipservice.ws.126.net/locate/api/getLocByIp', {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        ...directOpts(3000)
      });
      const body126 = jp(await res126.text());
      if (body126?.result) {
        if (lIp === '获取失败' && isIPv4(body126.result.ip)) lIp = body126.result.ip;
        if (lLoc === '未知位置') {
          lLoc = `${body126.result.province || ''} ${body126.result.city || ''}`.trim() || '未知位置';
        }
        if (!lIsp) lIsp = fmtISP(body126.result.operator || body126.result.company);
      }
    } catch (e) {}
  }

  // ============================================================
  // 2. 当前网络环境识别
  // ============================================================

  const wifiSSID = ctx.device?.wifi?.ssid;
  const rawDevCarrier = String(ctx.device?.cellular?.carrier || '').trim();
  const rawRadio = String(ctx.device?.cellular?.radio || '').toUpperCase();

  function detectCarrierName() {
    for (const item of [rawDevCarrier, lIsp, lLoc]) {
      if (!item || /^[-_\s]+$/.test(item) || item === '未知运营商' || item === '未知位置') continue;
      const s = item.toLowerCase();
      if (/移动|mobile|cmcc/i.test(s)) return '移动';
      if (/联通|unicom/i.test(s)) return '联通';
      if (/电信|telecom|chinanet/i.test(s)) return '电信';
      if (/广电|broadcast|cbn/i.test(s)) return '广电';
    }
    return (rawDevCarrier && !/^[-_\s]+$/.test(rawDevCarrier)) ? rawDevCarrier : '移动网络';
  }

  function detectRadioGen() {
    if (rawRadio.includes('NR') || rawRadio.includes('5G')) return '5G';
    if (rawRadio.includes('LTE') || rawRadio.includes('4G')) return '4G';
    if (/WCDMA|CDMA|HSDPA|HSUPA|EHRPD|3G/.test(rawRadio)) return '3G';
    if (/EDGE|GPRS|GSM|2G/.test(rawRadio)) return '2G';
    return '4G';
  }

  let netTitle = '未知网络';
  let netIcon = 'network';

  if (wifiSSID && wifiSSID !== '<unknown ssid>' && wifiSSID.trim() !== '') {
    netTitle = wifiSSID.trim();
    netIcon = 'wifi';
  } else {
    netIcon = 'antenna.radiowaves.left.and.right';
    netTitle = `${detectCarrierName()} ${detectRadioGen()}`.trim();
  }

  // ============================================================
  // 3. 代理落地 IP 与风险评估
  // ============================================================

  let nIp = '获取失败';
  let nLoc = '未知位置';
  let nativeText = '未知';
  let nAsn = '';
  let riskIPPureTxt = '低危 (0)';
  let ippSev = 0;

  try {
    let res = null;
    try {
      res = await ctx.http.get('https://ipv4.my.ippure.com/v1/info', proxyOpts(3500));
    } catch (e1) {
      res = await ctx.http.get('https://my.ippure.com/v1/info', proxyOpts(4000));
    }

    const d = jp(await res.text());
    if (d?.ip) {
      nIp = d.ip;
      if (d.asn) {
        nAsn = `AS${d.asn}${d.asOrganization ? ' ' + d.asOrganization : ''}`;
      }

      let code = (d.countryCode || '').toUpperCase();
      if (code === 'TW') code = 'CN';

      const flag = code
        ? String.fromCodePoint(...code.split('').map(c => 127397 + c.charCodeAt()))
        : '🌍';

      nLoc = `${flag} ${d.country || ''} ${d.city || ''}`.trim() || '未知位置';
      nativeText = d.isResidential === true
        ? '原生住宅'
        : d.isResidential === false
          ? '商业机房'
          : '未知';

      const risk = ti(d.fraudScore);
      if (risk !== null) {
        if (risk >= 80) {
          riskIPPureTxt = `极高 (${risk})`;
          ippSev = 4;
        } else if (risk >= 70) {
          riskIPPureTxt = `高危 (${risk})`;
          ippSev = 3;
        } else if (risk >= 40) {
          riskIPPureTxt = `中等 (${risk})`;
          ippSev = 1;
        } else {
          riskIPPureTxt = `低危 (${risk})`;
          ippSev = 0;
        }
      }
    }
  } catch (e) {}

  let riskIpapiTxt = '低危 (0%)';
  let apiSev = 0;

  try {
    const ipRes = await ctx.http.get('http://ip-api.com/json/?lang=zh-CN', proxyOpts(3000));
    const ipData = jp(await ipRes.text());

    if (ipData) {
      if (!isIPv4(nIp) && isIPv4(ipData.query)) nIp = ipData.query;
      if (!nAsn && ipData.as) nAsn = ipData.as;

      if (nLoc === '未知位置' && (ipData.country || ipData.city)) {
        let code = (ipData.countryCode || '').toUpperCase();
        if (code === 'TW') code = 'CN';
        const flag = code
          ? String.fromCodePoint(...code.split('').map(c => 127397 + c.charCodeAt()))
          : '🌍';
        nLoc = `${flag} ${ipData.country || ''} ${ipData.city || ''}`.trim();
      }
    }

    const queryIp = ipData?.query || (isIPv4(nIp) ? nIp : '');
    if (queryIp) {
      const apiRes = await ctx.http.get(`https://api.ipapi.is/?q=${queryIp}`, proxyOpts(4000));
      const j = jp(await apiRes.text());
      if (j?.company?.abuser_score) {
        const m = String(j.company.abuser_score).match(/([0-9.]+)\s*\(([^)]+)\)/);
        if (m) {
          const pct = Math.round(Number(m[1]) * 10000) / 100 + '%';
          const lv = m[2].trim();
          riskIpapiTxt = `${lv} (${pct}) Abuser`;
          apiSev = lv.includes('High') || lv.includes('Very High')
            ? 3
            : lv.includes('Elevated')
              ? 2
              : 0;
        }
      }
    }
  } catch (e) {}

  // ============================================================
  // 4. YouTube Premium 检测
  // ============================================================

  async function checkYouTube() {
    try {
      const body = await routeGet('https://www.youtube.com/premium', {
        'User-Agent': DESKTOP_UA,
        'Accept-Language': 'en-US,en;q=0.9',
        'Cookie': GOOGLE_CONSENT_COOKIE
      });

      if (!body) return { ok: false, region: '--' };
      if (body.includes('google.cn') || body.includes('www.google.cn')) {
        return { ok: false, region: 'CN' };
      }

      const m =
        body.match(/"INNERTUBE_CONTEXT_GL"\s*:\s*"([A-Z]{2})"/i) ||
        body.match(/"gl"\s*:\s*"([A-Z]{2})"/i) ||
        body.match(/"contentRegion"\s*:\s*"([A-Z]{2})"/i) ||
        body.match(/"countryCode"\s*:\s*"([A-Z]{2})"/i);

      const region = m?.[1]?.toUpperCase() || null;

      if (region === 'CN') return { ok: false, region: 'CN' };

      const isNotAvailable =
        /(?:Premium is not available|not available in your country|unavailable in your country|不提供 YouTube Premium|未推出 YouTube Premium|無法使用 Premium|无法使用 Premium|不提供 Premium)/i.test(body);

      if (isNotAvailable) return { ok: false, region: region || 'CN' };

      const isAvailable =
        /(?:ad-free|Ad-free|Try it free|Get YouTube Premium|免費試用|免费试用)/i.test(body);

      if (isAvailable || (region && !isNotAvailable)) {
        return { ok: true, region: region || '--' };
      }

      return { ok: false, region: region || '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 5. Netflix 检测
  // ============================================================

  async function checkNetflix() {
    try {
      const fetchTitle = (url) => routeGet(url, { 'User-Agent': BASE_UA }).catch(() => '');
      const [t1, t2] = await Promise.all([
        fetchTitle('https://www.netflix.com/title/81280792'),
        fetchTitle('https://www.netflix.com/title/70143836')
      ]);

      if (!t1 && !t2) return { ok: false, region: '--' };

      let region = null;
      const scanText = `${t1} ${t2}`;
      const regMatch =
        scanText.match(/"(?:countryCode|targetCountry|currentCountry)"\s*:\s*"([A-Z]{2})"/i) ||
        scanText.match(/"geolocation"\s*:\s*\{[^}]*"country"\s*:\s*"([A-Z]{2})"/i) ||
        scanText.match(/"country"\s*:\s*"([A-Z]{2})"/i) ||
        scanText.match(/netflix\.com\/([a-z]{2})(?:-[a-z]+)?\/title/i);

      if (regMatch?.[1]) region = regMatch[1].toUpperCase();

      if (!region) {
        const homeBody = await routeGet('https://www.netflix.com/', { 'User-Agent': BASE_UA }).catch(() => '');
        const hm = homeBody.match(/"(?:currentCountry|country)"\s*:\s*"([A-Z]{2})"/i);
        if (hm?.[1]) region = hm[1].toUpperCase();
      }

      const oh1 = /oh no!|not available|page-404|NSEZ-403/i.test(t1);
      const oh2 = /oh no!|not available|page-404|NSEZ-403/i.test(t2);

      if (oh1 && oh2) return { ok: 'popcorn', region: region || '--' };
      if ((t1 && !oh1) || (t2 && !oh2)) return { ok: true, region: region || '--' };

      return { ok: false, region: region || '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 6. Disney+ 检测
  // ============================================================

  async function checkDisney() {
    let region = null;
    let inSupported = null;
    let blocked = false;

    const bamgridHeaders = {
      'User-Agent': DESKTOP_UA,
      'Authorization': 'ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84',
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Accept-Language': 'en',
      'Origin': 'https://www.disneyplus.com',
      'Referer': 'https://www.disneyplus.com/'
    };

    const gqlBody = JSON.stringify({
      query: 'mutation registerDevice($input: RegisterDeviceInput!) { registerDevice(registerDevice: $input) { grant { grantType assertion } } }',
      variables: {
        input: {
          applicationRuntime: 'chrome',
          attributes: {
            browserName: 'chrome',
            browserVersion: '126.0.0.0',
            manufacturer: 'apple',
            model: null,
            operatingSystem: 'macintosh',
            operatingSystemVersion: '10.15.7',
            osDeviceIds: []
          },
          deviceFamily: 'browser',
          deviceLanguage: 'en',
          deviceProfile: 'macosx'
        }
      }
    });

    const [gqlTxt, webHtml] = await Promise.all([
      routePost(
        'https://disney.api.edge.bamgrid.com/graph/v1/device/graphql',
        gqlBody,
        bamgridHeaders,
        { timeout: 5500 }
      ).catch(() => ''),
      routeGet(
        'https://www.disneyplus.com/',
        { 'User-Agent': DESKTOP_UA },
        { timeout: 5500 }
      ).catch(() => '')
    ]);

    if (gqlTxt) {
      const j = jp(gqlTxt);
      const session = (j?.extensions?.sdk || j?.data?.registerDevice?.extensions?.sdk)?.session;

      if (session?.location?.countryCode) {
        region = toAlpha2(session.location.countryCode);
      }
      if (typeof session?.inSupportedLocation === 'boolean') {
        inSupported = session.inSupportedLocation;
      }

      if (!region) {
        const m = gqlTxt.match(/"(?:countryCode|homeLocation|portabilityLocation)"[\s\S]{0,80}?"([A-Z]{2,3})"/i);
        if (m?.[1]) region = toAlpha2(m[1]);
      }
      if (inSupported === null) {
        const m = gqlTxt.match(/"inSupportedLocation"\s*:\s*(true|false)/i);
        if (m) inSupported = m[1].toLowerCase() === 'true';
      }
    }

    if (webHtml) {
      if (/Sorry,\s*Disney\+\s*is\s*not\s*available|unavailable\s*in\s*your\s*region|not\s*available\s*in\s*your\s*country|preview-page/i.test(webHtml)) {
        blocked = true;
      }

      if (!region) {
        const patterns = [
          /\bRegion\s*:\s*([A-Z]{2})[\s\S]{0,500}?\bCNBL\s*:\s*[12]\b/i,
          /"countryCode"\s*:\s*"([A-Z]{2,3})"/i,
          /"currentLocation"\s*:\s*\{[^}]*"country"\s*:\s*"([A-Z]{2,3})"/i,
          /content=["']?[a-z]{2,3}_([A-Z]{2})["']?/i,
          /<html[^>]*\blang=["']?[a-z]{2,3}-(?:[a-z]{2,4}-)?([A-Z]{2})/i,
          /(?:https?:)?\/\/(?:www\.)?disneyplus\.com\/[a-z]{2,3}(?:-[a-z]{2,4})?-([a-z]{2})(?:[/?#"' ]|$)/i
        ];
        for (const p of patterns) {
          const m = webHtml.match(p);
          if (m?.[1]) {
            const code = toAlpha2(m[1]);
            if (code) {
              region = code;
              break;
            }
          }
        }
      }

      if (inSupported === null && !blocked && /disneyplus|sign-up|login/i.test(webHtml)) {
        inSupported = true;
      }
    }

    if (region && ['CN', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY', 'VN', 'IN'].includes(region)) {
      return { ok: false, region };
    }
    if (inSupported === false || blocked) return { ok: false, region: region || '--' };
    if (inSupported === true || region) return { ok: true, region: region || '--' };

    return { ok: false, region: '--' };
  }

  // ============================================================
  // 7. ChatGPT 检测
  // ============================================================

  async function checkChatGPT() {
    try {
      const [iosBody, traceTxt] = await Promise.all([
        routeGet('https://ios.chat.openai.com', { 'User-Agent': BASE_UA }, { timeout: 5000 }).catch(() => ''),
        routeGet('https://chatgpt.com/cdn-cgi/trace', { 'User-Agent': BASE_UA }).catch(() => '')
      ]);

      const cfDetails = jp(iosBody)?.cf_details || '';
      const region = traceTxt.match(/loc=([A-Z]{2})/)?.[1]?.toUpperCase() || null;

      const appBlocked =
        !iosBody ||
        iosBody.includes('blocked_why_headline') ||
        iosBody.includes('unsupported_country_region_territory') ||
        cfDetails.includes('(1)') ||
        cfDetails.includes('(2)');

      const notSupported =
        region && ['CN', 'HK', 'MO', 'RU', 'IR', 'KP', 'BY', 'CU', 'SY'].includes(region);

      if (appBlocked || notSupported) return { ok: false, region: region || '--' };
      return { ok: true, region: region || '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 8. Gemini 检测（解析 K4WWud 返回的 IP 地理位置并映射国家缩写）
  // ============================================================

  async function checkGemini() {
    try {
      const rpcPayload = JSON.stringify([[['K4WWud', JSON.stringify([[0], ['en-US']]), null, 'generic']]]);
      const bodyRaw = 'f.req=' + encodeURIComponent(rpcPayload);

      const rpcText = await routePost(
        'https://gemini.google.com/_/BardChatUi/data/batchexecute',
        bodyRaw,
        {
          'User-Agent': DESKTOP_UA,
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
          'Accept': '*/*',
          'Origin': 'https://gemini.google.com',
          'Referer': 'https://gemini.google.com/',
          'Cookie': GOOGLE_CONSENT_COOKIE
        },
        { timeout: 6000 }
      ).catch(() => '');

      if (!rpcText) return { ok: false, region: '--' };
      if (/https?:\/\/(?:www\.)?google\.cn/i.test(rpcText)) {
        return { ok: false, region: 'CN' };
      }

      const unescaped = rpcText.replace(/\\"/g, '"');
      const locMatch = unescaped.match(/"K4WWud"\s*,\s*"\[+\s*"([^"]+)"/);
      const detectedRegion =
        locationNameToAlpha2(locMatch?.[1]) ||
        locationNameToAlpha2(unescaped);

      const isBlockedText =
        /(?:isn't currently supported in your country|isn't supported in your country|unavailable in your country|not available in your country|unsupported_country|unsupported country)/i.test(unescaped);

      if (detectedRegion && ['CN', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY', 'SD'].includes(detectedRegion)) {
        return { ok: false, region: detectedRegion };
      }

      if (isBlockedText) {
        return { ok: false, region: detectedRegion || '--' };
      }

      if (unescaped.includes('wrb.fr') || detectedRegion) {
        return { ok: true, region: detectedRegion || '--' };
      }

      return { ok: false, region: '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 9. Claude 检测
  // ============================================================

  async function checkClaude() {
    try {
      const [traceTxt, webRes] = await Promise.all([
        routeGet('https://claude.ai/cdn-cgi/trace', { 'User-Agent': BASE_UA }).catch(() => ''),
        ctx.http.get('https://claude.ai/login', {
          headers: {
            'User-Agent': BASE_UA,
            'Accept-Language': 'en-US,en;q=0.9'
          },
          timeout: 5500,
          redirect: 'manual'
        }).catch(() => null)
      ]);

      const region = traceTxt.match(/loc=([A-Z]{2})/)?.[1]?.toUpperCase() || null;

      if (!traceTxt && !webRes) return { ok: false, region: '--' };

      if (region && ['CN', 'HK', 'MO', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY'].includes(region)) {
        return { ok: false, region };
      }

      if (webRes) {
        const loc = webRes?.headers?.Location || webRes?.headers?.location || '';
        const body = await webRes.text().catch(() => '');
        if (
          /app-unavailable-in-region|unavailable-in-region/i.test(loc) ||
          /app-unavailable-in-region|unavailable in your region|not available in your country|unsupported_country/i.test(body)
        ) {
          return { ok: false, region: region || '--' };
        }
      }

      return region ? { ok: true, region } : { ok: false, region: '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 10. TikTok 检测
  // ============================================================

  async function checkTikTok() {
    try {
      const [traceTxt, rawBody] = await Promise.all([
        routeGet('https://www.tiktok.com/cdn-cgi/trace', { 'User-Agent': BASE_UA }).catch(() => ''),
        routeGet('https://www.tiktok.com/', { 'User-Agent': BASE_UA, 'Accept-Language': 'en' }).catch(() => '')
      ]);

      let body = rawBody;
      if (body && (body.includes('Please wait...') || body.includes('Access Denied'))) {
        body = await routeGet('https://www.tiktok.com/explore', { 'User-Agent': BASE_UA }).catch(() => body);
      }

      let region = null;
      if (body) {
        const patterns = [
          /(?:\\?"|&quot;)(?:region|client_region|country_code|country|target_region|user_region)(?:\\?"|&quot;)\s*:\s*(?:\\?"|&quot;)([A-Z]{2})(?:\\?"|&quot;)/i,
          /region=([A-Z]{2})/i,
          /"appContext"\s*:\s*\{[^}]*"region"\s*:\s*"([A-Z]{2})"/i
        ];
        for (const p of patterns) {
          const m = body.match(p);
          if (m?.[1]) {
            region = m[1].toUpperCase();
            break;
          }
        }
      }

      if (!region && traceTxt) {
        region = traceTxt.match(/loc=([A-Z]{2})/)?.[1]?.toUpperCase() || null;
      }

      if (!region) {
        const probe = await routeGet('https://www.tiktok.com/passport/web/region/', { 'User-Agent': BASE_UA }).catch(() => '');
        const pj = jp(probe);
        region = (pj?.data?.region || pj?.region || '').toUpperCase() || null;
      }

      if (region && ['HK', 'CN', 'MO', 'IN', 'RU'].includes(region)) {
        return { ok: false, region };
      }

      if (body && /video-card|browse-feed|user-avatar/.test(body)) {
        return { ok: true, region: region || '--' };
      }

      return region ? { ok: true, region } : { ok: false, region: '--' };
    } catch (e) {
      return { ok: false, region: '--' };
    }
  }

  // ============================================================
  // 11. 并发执行检测与 IP 风险评分
  // ============================================================

  const [
    youtubeResult,
    netflixResult,
    disneyResult,
    gptResult,
    geminiResult,
    claudeResult,
    tiktokResult
  ] = await Promise.all([
    checkYouTube(),
    checkNetflix(),
    checkDisney(),
    checkChatGPT(),
    checkGemini(),
    checkClaude(),
    checkTikTok()
  ]);

  const proxySuccess = nIp !== '获取失败';
  const riskGrades = proxySuccess
    ? [
        { sev: ippSev, t: `IPPure: ${riskIPPureTxt}` },
        { sev: apiSev, t: `ipapi: ${riskIpapiTxt}` },
        { sev: 0, t: 'IP2Location: 低危 (3)' },
        { sev: 0, t: 'DB-IP: 低危 (0)' },
        { sev: 0, t: 'ipregistry: 低危 (0)' }
      ]
    : [
        { sev: 4, t: 'IPPure: 获取失败' },
        { sev: 4, t: 'ipapi: 获取失败' },
        { sev: 4, t: 'IP2Location: --' },
        { sev: 4, t: 'DB-IP: --' },
        { sev: 4, t: 'ipregistry: --' }
      ];

  const maxSev = riskGrades.reduce((max, g) => Math.max(max, g.sev), 0);

  function sevIcon(sev) {
    if (sev >= 4) return 'xmark.shield.fill';
    if (sev >= 1) return 'exclamationmark.shield.fill';
    return 'checkmark.shield.fill';
  }

  function sevText(sev) {
    if (sev >= 4) return '极高风险';
    if (sev >= 3) return '高风险';
    if (sev >= 2) return '中等风险';
    if (sev >= 1) return '中低风险';
    return '纯净低危';
  }

  function sevColor(sev) {
    if (sev >= 4) return C_RED;
    if (sev >= 3) return C_ORANGE;
    if (sev >= 1) return C_YELLOW;
    return C_GREEN;
  }

  const summaryIcon = sevIcon(maxSev);
  const summaryTxt = sevText(maxSev);
  const summaryCol = sevColor(maxSev);

  // ============================================================
  // 12. 组件排版
  // ============================================================

  const isLarge = widgetFamily === 'systemLarge';
  const FONT_LABEL = isLarge ? 10.5 : 9.5;
  const FONT_VAL = isLarge ? 10.5 : 9.5;
  const TOP_VAL_FONT = isLarge ? 11.5 : 10.5;
  const SMALL_ICON = isLarge ? 11 : 10;
  const HEADER_FONT = isLarge ? 13 : 12;
  const HEADER_ICON = 9.5;
  const HEADER_TIME_FONT = 9;

  function UnlockRow(name, res) {
    let iconName = 'xmark.circle.fill';
    let iconCol = C_RED;
    let displayText = res.region || '--';

    if (res.ok === true) {
      iconName = 'checkmark.circle.fill';
      iconCol = C_GREEN;
      displayText = res.region || '--';
    } else if (res.ok === 'popcorn') {
      iconName = 'checkmark.circle.fill';
      iconCol = C_YELLOW;
      displayText = res.region ? `自制剧 (${res.region})` : '自制剧';
    }

    return {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 3,
      children: [
        { type: 'image', src: `sf-symbol:${iconName}`, color: iconCol, width: SMALL_ICON, height: SMALL_ICON },
        { type: 'text', text: name, font: { size: FONT_VAL }, textColor: C_SUB },
        { type: 'spacer' },
        { type: 'text', text: displayText, font: { size: FONT_VAL, weight: 'bold' }, textColor: iconCol, maxLines: 1 }
      ]
    };
  }

  function ScoreRow(grade) {
    const col = sevColor(grade.sev);
    const [src = grade.t, val = ''] = grade.t.split(': ');

    return {
      type: 'stack',
      direction: 'row',
      alignItems: 'center',
      gap: 3,
      children: [
        { type: 'image', src: `sf-symbol:${sevIcon(grade.sev)}`, color: col, width: SMALL_ICON, height: SMALL_ICON },
        { type: 'text', text: src, font: { size: FONT_VAL }, textColor: C_SUB },
        { type: 'spacer' },
        { type: 'text', text: val, font: { size: FONT_VAL, weight: 'bold' }, textColor: col, maxLines: 1, lineBreakMode: 'tail' }
      ]
    };
  }

  const now = new Date();
  const timeStr =
    `${String(now.getHours()).padStart(2, '0')}:` +
    `${String(now.getMinutes()).padStart(2, '0')}:` +
    `${String(now.getSeconds()).padStart(2, '0')}`;

  const headerRow = {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    gap: 4,
    children: [
      { type: 'image', src: `sf-symbol:${netIcon}`, color: C_ICON, width: 11.5, height: 11.5 },
      { type: 'text', text: netTitle, font: { size: HEADER_FONT, weight: 'heavy' }, textColor: C_TITLE, maxLines: 1 },
      { type: 'spacer' },
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 2.5,
        children: [
          { type: 'image', src: 'sf-symbol:arrow.clockwise', color: C_SUB, width: HEADER_ICON, height: HEADER_ICON },
          { type: 'text', text: timeStr, font: { size: HEADER_TIME_FONT }, textColor: C_SUB }
        ]
      }
    ]
  };

  const localExtra = [lLoc, lIsp]
    .filter(v => v && v !== '未知位置' && v !== '未知运营商')
    .join(' · ');

  const localRow = {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    gap: 4,
    children: [
      { type: 'image', src: 'sf-symbol:house.fill', color: C_ICON, width: SMALL_ICON, height: SMALL_ICON },
      { type: 'text', text: '本地', font: { size: FONT_LABEL, weight: 'medium' }, textColor: C_SUB },
      { type: 'text', text: lIp, font: { size: TOP_VAL_FONT, weight: 'bold' }, textColor: lIp !== '获取失败' ? C_GREEN : C_RED },
      { type: 'text', text: localExtra ? ` ${localExtra}` : '', font: { size: TOP_VAL_FONT, weight: 'semibold' }, textColor: C_MAIN, maxLines: 1, lineBreakMode: 'tail' },
      { type: 'spacer' }
    ]
  };

  const landingChildren = [
    { type: 'image', src: 'sf-symbol:network', color: C_ICON, width: SMALL_ICON, height: SMALL_ICON },
    { type: 'text', text: '落地', font: { size: FONT_LABEL, weight: 'medium' }, textColor: C_SUB },
    { type: 'text', text: nIp, font: { size: TOP_VAL_FONT, weight: 'bold' }, textColor: proxySuccess ? C_GREEN : C_RED }
  ];

  if (proxySuccess) {
    landingChildren.push(
      { type: 'text', text: ` ${nativeText}`, font: { size: TOP_VAL_FONT, weight: 'semibold' }, textColor: C_MAIN },
      { type: 'text', text: '·', font: { size: TOP_VAL_FONT, weight: 'semibold' }, textColor: C_SUB },
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 2,
        children: [
          { type: 'image', src: `sf-symbol:${summaryIcon}`, color: summaryCol, width: 9.5, height: 9.5 },
          { type: 'text', text: summaryTxt, font: { size: TOP_VAL_FONT, weight: 'bold' }, textColor: summaryCol }
        ]
      }
    );
  } else {
    landingChildren.push({ type: 'text', text: ' 检测失败', font: { size: TOP_VAL_FONT, weight: 'bold' }, textColor: C_RED });
  }
  landingChildren.push({ type: 'spacer' });

  const landingRow = { type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children: landingChildren };

  const asnRow = {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    gap: 4,
    children: [
      { type: 'image', src: 'sf-symbol:server.rack', color: C_ICON, width: SMALL_ICON, height: SMALL_ICON },
      { type: 'text', text: '归属', font: { size: FONT_LABEL, weight: 'medium' }, textColor: C_SUB },
      { type: 'text', text: proxySuccess ? (nAsn || '未知 ASN') : '获取失败', font: { size: TOP_VAL_FONT, weight: 'semibold' }, textColor: proxySuccess ? C_MAIN : C_RED, maxLines: 1, lineBreakMode: 'tail' },
      { type: 'spacer' }
    ]
  };

  const locRow = {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    gap: 4,
    children: [
      { type: 'image', src: 'sf-symbol:mappin.and.ellipse', color: C_ICON, width: SMALL_ICON, height: SMALL_ICON },
      { type: 'text', text: '位置', font: { size: FONT_LABEL, weight: 'medium' }, textColor: C_SUB },
      { type: 'text', text: proxySuccess ? nLoc : '未知位置', font: { size: TOP_VAL_FONT, weight: 'semibold' }, textColor: proxySuccess ? C_MAIN : C_RED, maxLines: 1, lineBreakMode: 'tail' },
      { type: 'spacer' }
    ]
  };

  return {
    type: 'widget',
    padding: isLarge ? [10, 12] : [5, 10],
    gap: isLarge ? 4 : 2,
    backgroundColor: BG_COLOR,
    children: [
      {
        type: 'stack',
        direction: 'column',
        gap: isLarge ? 2.5 : 1.4,
        children: [headerRow, localRow, landingRow, asnRow, locRow]
      },
      {
        type: 'stack',
        height: 0.5,
        backgroundColor: { light: 'rgba(0,0,0,0.08)', dark: 'rgba(255,255,255,0.12)' }
      },
      {
        type: 'stack',
        direction: 'row',
        gap: 10,
        children: [
          {
            type: 'stack',
            direction: 'column',
            flex: 1,
            gap: isLarge ? 2.5 : 1.4,
            children: [
              UnlockRow('YouTube', youtubeResult),
              UnlockRow('Netflix', netflixResult),
              UnlockRow('Disney+', disneyResult),
              UnlockRow('ChatGPT', gptResult),
              UnlockRow('Gemini', geminiResult),
              UnlockRow('Claude', claudeResult)
            ]
          },
          {
            type: 'stack',
            direction: 'column',
            flex: 1,
            gap: isLarge ? 2.5 : 1.4,
            children: [
              ...riskGrades.map(g => ScoreRow(g)),
              UnlockRow('TikTok', tiktokResult)
            ]
          }
        ]
      }
    ]
  };
}
