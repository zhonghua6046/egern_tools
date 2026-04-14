/**
 * 🌤️ 和风天气 - Egern 小组件 (极简原生风格 · 坐标完美支持版)
 * 非原创，改编自：https://raw.githubusercontent.com/IBL3ND/module/refs/heads/main/Weather_Widget.JS
 * ⚠️ 环境变量说明：
 * KEY: 和风天气 API Key（必填）
 * API_HOST: 你的个人API Host（必填！从控制台获取）
 * LOCATION: 城市名 (如 "长沙") 或 经纬度坐标 (如 "113.12,23.02")
 */

export default async function(ctx) {
  const env = ctx.env || {};
  const widgetFamily = ctx.widgetFamily || 'systemMedium';

  const apiKey     = (env.KEY || '').trim();
  const apiHostRaw = (env.API_HOST || '').trim();
  const location   = (env.LOCATION || '北京').trim();

  if (!apiKey)     return renderError('缺少 KEY 环境变量');
  if (!apiHostRaw) return renderError('缺少 API_HOST 环境变量');

  const apiHost = normalizeHost(apiHostRaw);

  try {
    // 1. 获取经纬度和格式化后的城市名
    const { lon, lat, city } = await getLocation(ctx, location, apiKey, apiHost);
    
    // 2. 并发获取：实时天气、3天预报(取今日最高低)、空气质量
    const [now, daily, air] = await Promise.all([
      fetchWeatherNow(ctx, apiKey, lon, lat, apiHost),
      fetchDailyWeather(ctx, apiKey, lon, lat, apiHost),
      (widgetFamily !== 'systemSmall' && !isAccessoryFamily(widgetFamily))
        ? fetchAirQuality(ctx, apiKey, lon, lat, apiHost)
        : Promise.resolve(null)
    ]);

    // 3. 根据尺寸分发渲染逻辑 (极简原生UI)
    if (isAccessoryFamily(widgetFamily)) {
      return renderAccessoryCompact(now, city, widgetFamily);
    }

    if (widgetFamily === 'systemSmall') {
      return renderSmall(now, daily, city);
    } else {
      return renderMedium(now, air, daily, city);
    }

  } catch (e) {
    console.error(e);
    return renderError(`请求失败：${e.message.slice(0, 60)}`);
  }
}

// --------------------------------------------------------
// UI 渲染逻辑 (极简原生风)
// --------------------------------------------------------

function renderMedium(now, air, daily, city) {
  const icon = getWeatherIcon(now.icon);
  const iconColor = getWeatherColor(now.icon);
  const aqiColor = air.color;
  const time = new Date();
  const timeStr = `${time.getMonth()+1}/${time.getDate()} ${time.getHours()}:${String(time.getMinutes()).padStart(2,'0')}`;

  return {
    type: 'widget',
    padding: 16,
    gap: 12,
    backgroundColor: { light: '#FFFFFF', dark: '#2C2C2E' },
    children: [
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 8,
        children: [
          {
            type: 'stack',
            direction: 'row',
            alignItems: 'center',
            gap: 4,
            children: [
              { type: 'image', src: 'sf-symbol:location.fill', width: 14, height: 14, color: { light: '#FF3B30', dark: '#FF453A' } },
              { type: 'text', text: city, font: { size: 18, weight: 'bold' }, textColor: { light: '#000', dark: '#FFF' }, lineLimit: 1 }
            ]
          },
          { type: 'spacer' },
          {
            type: 'text',
            text: `AQI ${air.aqi}`,
            font: { size: 14, weight: 'semibold' },
            textColor: aqiColor
          },
          { type: 'text', text: timeStr, font: { size: 11 }, textColor: { light: '#8E8E93', dark: '#8E8E93' } }
        ]
      },
      {
        type: 'stack',
        direction: 'row',
        alignItems: 'center',
        gap: 16,
        children: [
          { type: 'image', src: `sf-symbol:${icon}`, width: 68, height: 68, color: iconColor },
          {
            type: 'stack',
            direction: 'column',
            flex: 1,
            gap: 2,
            children: [
              { type: 'text', text: `${now.temp}°C`, font: { size: 36, weight: 'bold' }, textColor: { light: '#000', dark: '#FFF' } },
              { type: 'text', text: `${now.text} · ${daily.min}°/${daily.max}°`, font: { size: 16 }, textColor: { light: '#666', dark: '#CCC' } }
            ]
          },
          {
            type: 'stack',
            direction: 'column',
            alignItems: 'center',
            gap: 2,
            children: [
              { type: 'text', text: '空气', font: { size: 11 }, textColor: { light: '#666', dark: '#AAA' } },
              { type: 'text', text: air.category, font: { size: 18, weight: 'bold' }, textColor: aqiColor }
            ]
          }
        ]
      },
      {
        type: 'stack',
        direction: 'row',
        gap: 10,
        children: [
          createInfoItem('drop.fill',   '湿度', `${now.humidity}%`, '#007AFF'),
          createInfoItem('wind',        '风向', `${now.windDir} ${now.windScale}级`, '#5856D6'),
          createInfoItem('thermometer', '体感', `${now.feelsLike}°C`, '#FF9500')
        ]
      }
    ]
  };
}

function renderSmall(now, daily, city) {
  const icon = getWeatherIcon(now.icon);
  return {
    type: 'widget',
    padding: 14,
    backgroundColor: { light: '#FFFFFF', dark: '#000000' },
    children: [
      { type: 'text', text: city, font: { size: 14, weight: 'bold' }, lineLimit: 1 },
      { type: 'image', src: `sf-symbol:${icon}`, width: 34, height: 34 },
      { type: 'text', text: `${now.temp}°`, font: { size: 28, weight: 'bold' } },
      { type: 'text', text: `${daily.min}°/${daily.max}°`, font: { size: 12 }, textColor: { light: '#666', dark: '#AAA' } }
    ]
  };
}

function renderAccessoryCompact(now, city, family) {
  return { type: 'widget', children: [{ type: 'text', text: `${now.temp}° ${city}` }] };
}

function renderError(msg) {
  return { type: 'widget', padding: 16, children: [{ type: 'text', text: msg, textColor: { light: '#FF3B30', dark: '#FF453A' } }] };
}

function createInfoItem(icon, label, value, iconColor) {
  return {
    type: 'stack',
    direction: 'row',
    alignItems: 'center',
    flex: 1,
    gap: 5,
    children: [
      { type: 'image', src: `sf-symbol:${icon}`, width: 20, height: 20, color: { light: iconColor, dark: iconColor } },
      {
        type: 'stack',
        direction: 'column',
        children: [
          { type: 'text', text: label, font: { size: 10 }, textColor: { light: '#666', dark: '#AAA' } },
          { type: 'text', text: value, font: { size: 15, weight: 'semibold' }, textColor: { light: '#000', dark: '#FFF' }, lineLimit: 1 }
        ]
      }
    ]
  };
}

// --------------------------------------------------------
// 核心数据处理逻辑
// --------------------------------------------------------

function normalizeHost(host) {
  let h = host;
  if (!/^https?:\/\//i.test(h)) h = 'https://' + h;
  return h.replace(/\/+$/, '');
}

function isAccessoryFamily(family) {
  return family.startsWith('accessory');
}

async function getLocation(ctx, locName, key, host) {
  // 仅保留核心热门城市直出，出差去小城市或填坐标会走下方 API 精准查询
  const presets = {
    '北京': { lon: '116.4074', lat: '39.9042' }, '上海': { lon: '121.4737', lat: '31.2304' },
    '广州': { lon: '113.2644', lat: '23.1291' }, '深圳': { lon: '114.0579', lat: '22.5431' },
    '佛山': { lon: '113.1214', lat: '23.0215' }, '长沙': { lon: '112.9388', lat: '28.2282' },
    '成都': { lon: '104.0657', lat: '30.6595' }, '武汉': { lon: '114.2986', lat: '30.5844' }
  };

  if (presets[locName]) return { ...presets[locName], city: locName };

  // 判断输入是否看起来像经纬度 (如 113.12,23.02)
  const isCoordinates = /[,\.]/.test(locName) && /\d/.test(locName);

  try {
    const url = `${host}/geo/v2/city/lookup?location=${encodeURIComponent(locName)}&key=${key}&number=1&lang=zh`;
    const resp = await ctx.http.get(url, { timeout: 6000 });
    const data = await resp.json();
    if (data.code === '200' && data.location?.[0]) {
      const loc = data.location[0];
      // 成功解析出城市名
      return { lon: loc.lon, lat: loc.lat, city: loc.name };
    }
  } catch {}

  // 兜底逻辑：网络失败且输入的是坐标，显示"定位中"防止暴露数字
  const fallbackCity = isCoordinates ? '定位中' : (locName || '北京');
  
  if (isCoordinates) {
      const parts = locName.split(',');
      if(parts.length === 2) {
          return { lon: parts[0].trim(), lat: parts[1].trim(), city: fallbackCity };
      }
  }

  return { lon: '116.4074', lat: '39.9042', city: fallbackCity };
}

async function fetchWeatherNow(ctx, key, lon, lat, host) {
  const url = `${host}/v7/weather/now?location=${lon},${lat}&key=${key}&lang=zh`;
  const resp = await ctx.http.get(url, { timeout: 8000 });
  const data = await resp.json();
  if (data.code !== '200') throw new Error(data.msg || `接口返回 ${data.code}`);
  return {
    temp: data.now.temp,
    feelsLike: data.now.feelsLike || data.now.temp, // 提取体感温度
    text: data.now.text,
    icon: data.now.icon,
    humidity: data.now.humidity,
    windDir: data.now.windDir || '--',
    windScale: data.now.windScale || '--',
    windSpeed: data.now.windSpeed || '--'
  };
}

async function fetchDailyWeather(ctx, key, lon, lat, host) {
  try {
    const url = `${host}/v7/weather/3d?location=${lon},${lat}&key=${key}&lang=zh`;
    const resp = await ctx.http.get(url, { timeout: 8000 });
    const data = await resp.json();
    if (data.code === '200' && data.daily?.length > 0) {
      return { min: data.daily[0].tempMin, max: data.daily[0].tempMax };
    }
  } catch (e) {}
  return { min: '--', max: '--' };
}

async function fetchAirQuality(ctx, key, lon, lat, host) {
  let aqiData = null;
  try {
    const url = `${host}/airquality/v1/current/${lat}/${lon}?key=${key}&lang=zh`;
    const resp = await ctx.http.get(url, { timeout: 7000 });
    const data = await resp.json();
    if (data.indexes && data.indexes.length > 0) {
      const cnMee = data.indexes.find(i => i.code === 'cn-mee') || data.indexes[0];
      aqiData = { aqi: Math.round(Number(cnMee.aqi)), category: cnMee.category || getAQICategory(cnMee.aqi).text, color: getAQICategory(cnMee.aqi).color };
    }
  } catch (e) {}
  return aqiData || { aqi: '--', category: '--', color: { light: '#999', dark: '#888' } };
}

function getAQICategory(val) {
  const n = Number(val);
  if (isNaN(n)) return { text: '--', color: { light: '#999999', dark: '#888888' } };
  if (n <=  50) return { text: '优', color: { light: '#4CD964', dark: '#34C759' } };
  if (n <= 100) return { text: '良', color: { light: '#FFCC00', dark: '#FF9F0A' } };
  return { text: '轻度', color: { light: '#FF9500', dark: '#FF9500' } };
}

function getWeatherIcon(code) {
  const map = { '100': 'sun.max.fill', '101': 'cloud.sun.fill', '104': 'cloud.fill', '305': 'cloud.rain.fill' };
  return map[code] || 'cloud.fill';
}

function getWeatherColor(code) {
  const n = Number(code);
  if (n >= 100 && n <= 104) return { light: '#FF9500', dark: '#FFB340' };
  return { light: '#007AFF', dark: '#0A84FF' };
}
