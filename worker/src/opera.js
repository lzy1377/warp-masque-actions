// Opera VPN (SurfEasy) 匿名注册与落地发现。
// 坑一: API 用 Digest 认证不是 Basic，要先吃一个 401 拿 nonce。
// 坑二: 服务端声明 algorithm="SHA-256"，不是 Digest 默认的 MD5。
//       按服务端声明的算法走，同时保留 MD5 兜底。
// 坑三: Workers 的 fetch 不自动管 cookie，会话得手工维持。
import { md5Hex } from "./md5.js";

const EP = "https://api2.sec-tunnel.com/v4";
const API_USER = "se0316";
const API_PASS = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II";
const CLIENT_TYPE = "se0316";
const H = {
  "SE-Client-Version": "Stable 114.0.5282.21",
  "SE-Operating-System": "Windows",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
  "Content-Type": "application/x-www-form-urlencoded",
  "Accept": "application/json",
};

export const REGIONS = { AS: "亚洲", EU: "欧洲", AM: "美洲" };

/** discover 的 requested_geo 对齐社区格式 `"XX",,`——裸码会命中服务端
 *  AM 回退池，导致"亚洲组挂欧美 IP"。反引号在 URLSearchParams 编码里
 *  会被原样传递，服务端能认到。 */
const geoParam = (code) => `"${code}",,`;

/** 服务端顶层错误字段 return_code 判断："0" 键=成功，其他键=错误码。
 *  注意是对象 {"0":"OK"}，不是裸字符串/数字；个别情况下可能是数字 0。
 *  没有该字段时不拦（兼容未知响应）。 */
function returnCodeOk(rc) {
  if (rc == null) return true;
  if (typeof rc === "number") return rc === 0;
  if (typeof rc === "string") return rc === "0";
  if (typeof rc === "object") return Object.prototype.hasOwnProperty.call(rc, "0");
  return true;
}

/** discover 响应里一台落地服务器的真实区码。拿不到就当没有。 */
export function landingGeo(x) {
  return x && x.geo && typeof x.geo.country_code === "string"
    ? x.geo.country_code.toUpperCase()
    : "";
}

/** 把某区 discover 响应转成落地条目。真实区码以响应 geo.country_code 为准：
 *  空/缺字段才回落请求码，避免"亚洲组挂欧美 IP"那种错配。
 *  counters 按真实区码累计序号（跨区共享），tag/SNI 才不打架。 */
export function landingsFromDisco(disc, reqCode, counters) {
  const out = [];
  // 只在成功响应（return_code 有 "0" 键）且 ips 存在时取值；
  // 非 0 错误（如 801）或缺 ips 一律产出 0 条
  const rc = disc && disc.return_code;
  if (rc == null || !returnCodeOk(rc)) return out;
  const ips = (disc && disc.data && disc.data.ips) || [];
  for (const x of ips) {
    const cc = landingGeo(x) || reqCode;
    const loc = REGIONS[cc] || REGIONS[reqCode];
    const seq = (counters[cc] = (counters[cc] || 0) + 1);
    out.push({
      tag: `${loc}${seq}`,
      loc,
      ip: x.ip,
      port: x.ports?.[0] ?? x.port ?? 443,
      host: `${cc.toLowerCase()}${seq - 1}.sec-tunnel.com`,
    });
  }
  return out;
}

/** Digest 的 H()。服务端目前用 SHA-256，老实现是 MD5，两个都支持。 */
async function digestHash(algo, s) {
  if (/^md5$/i.test(algo)) return md5Hex(s);
  const name = /512/.test(algo) ? "SHA-512" : "SHA-256";
  const d = await crypto.subtle.digest(name, new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha1Upper(s) {
  const d = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(d)]
    .map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function randHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

class Session {
  constructor() { this.jar = ""; }

  _absorb(r) {
    const sc = r.headers.getSetCookie?.() || [];
    if (sc.length) this.jar = sc.map((c) => c.split(";")[0]).join("; ");
  }

  async rpc(path, params) {
    const url = `${EP}/${path}`;
    const body = new URLSearchParams(params).toString();
    const base = () => ({ ...H, ...(this.jar ? { Cookie: this.jar } : {}) });

    let r = await fetch(url, { method: "POST", headers: base(), body });
    if (r.status === 401) {
      const wa = r.headers.get("www-authenticate") || "";
      const g = (k) => (wa.match(new RegExp(`${k}="([^"]*)"`)) || [])[1] || "";
      const realm = g("realm"), nonce = g("nonce"), qop = g("qop"), opaque = g("opaque");
      // algorithm 可能不带引号，两种写法都认
      const algo = g("algorithm") ||
        (wa.match(/algorithm=([\w-]+)/) || [])[1] || "MD5";
      const uri = new URL(url).pathname;
      const cnonce = randHex(8), nc = "00000001";
      const H1 = await digestHash(algo, `${API_USER}:${realm}:${API_PASS}`);
      const H2 = await digestHash(algo, `POST:${uri}`);
      const q = qop ? qop.split(",")[0].trim() : "";
      const resp = q
        ? await digestHash(algo, `${H1}:${nonce}:${nc}:${cnonce}:${q}:${H2}`)
        : await digestHash(algo, `${H1}:${nonce}:${H2}`);
      let a = `Digest username="${API_USER}", realm="${realm}", nonce="${nonce}", ` +
              `uri="${uri}", response="${resp}", algorithm=${algo}`;
      if (q) a += `, qop=${q}, nc=${nc}, cnonce="${cnonce}"`;
      if (opaque) a += `, opaque="${opaque}"`;
      this._absorb(r);
      r = await fetch(url, {
        method: "POST",
        headers: { ...base(), Authorization: a },
        body,
      });
    }
    this._absorb(r);
    if (!r.ok) throw new Error(`${path} HTTP ${r.status}`);
    const j = await r.json();
    // 服务端顶层错误字段是 return_code：`{"0":"OK"}` 成功，非 0 键失败
    // （实测 801 = "No Available Proxies for Region"）。不存在 status 字段，
    // 老的判断永远不触发，属于白写。discover 的非 0 错误按整区失败处理，
    // 此处不抛，由调用方看 return_code 决定跳过。
    if (path === "discover" && j?.return_code && !returnCodeOk(j.return_code)) {
      return j;
    }
    if (!returnCodeOk(j?.return_code)) {
      const code = j && j.return_code && typeof j.return_code === "object"
        ? Object.keys(j.return_code)[0]
        : JSON.stringify(j?.return_code);
      throw new Error(`${path} return_code=${code}`);
    }
    return j;
  }
}

/** 匿名注册一个 Opera 账号，返回全部大区的落地清单和代理凭据。 */
export async function fetchOpera() {
  const s = new Session();

  // 邮箱随机，密码就是邮箱的 SHA-1 大写
  const email = `${randHex(10)}@${CLIENT_TYPE}.best.vpn`;
  await s.rpc("register_subscriber", { email, password: await sha1Upper(email) });

  const dev = await s.rpc("register_device", {
    client_type: CLIENT_TYPE,
    device_hash: randHex(20).toUpperCase(),
    device_name: "Opera-Browser-Client",
  });
  const deviceId = dev.data.device_id;
  const idHash = await sha1Upper(deviceId);

  const gp = await s.rpc("device_generate_password", { device_id: deviceId });
  const password = gp.data.device_password;

  const byReq = {};   // 分请求码统计，给 state:meta 排查用
  const landings = [];
  const counters = {};
  for (const [reqCode] of Object.entries(REGIONS)) {
    let disc;
    let failed = false;
    try {
      // 对齐社区格式 `"XX",,`，裸码会命中服务端 AM 回退池
      disc = await s.rpc("discover", { serial_no: idHash, requested_geo: geoParam(reqCode) });
    } catch {
      failed = true;    // 传输/解析层失败：该区记 0
    }
    if (failed || !returnCodeOk(disc?.return_code)) {
      // 该区没有可用落地（如 801）或请求失败：跳过，不影响其他区
      byReq[reqCode] = 0;
      continue;
    }
    const ips = (disc.data && disc.data.ips) || [];
    byReq[reqCode] = ips.length;
    landings.push(...landingsFromDisco(disc, reqCode, counters));
  }

  return {
    username: idHash, password, landings,
    perRegion: byReq,               // 各请求码 discover 成功/数量（0 = 失败）
    fetchedAt: new Date().toISOString(),
  };
}
