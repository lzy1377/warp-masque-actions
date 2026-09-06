// opera.js 修复的单元测试：requested_geo 格式、真实区码驱动分组/SNI、
// return_code 判错、各区 discover 数量统计。
// 跑: node test/opera.test.mjs
import { REGIONS, landingGeo, landingsFromDisco } from "../src/opera.js";

let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗", n)); };

// landingsFromDisco: 真实 geo.country_code 决定 loc/tag/SNI，空字段回落请求码
{
  const disc = {
    return_code: { "0": "OK" },
    data: { ips: [
      { ip: "1.1.1.1", geo: { country_code: "AS" }, ports: [443] },
      { ip: "2.2.2.2" },
    ] },
  };
  const ls = landingsFromDisco(disc, "EU", {});
  t("落地条目数量 = ips 数量", ls.length === 2);

  const [a, b] = ls;
  t("真实区码 AS 决定 tag/loc", a.tag === "亚洲1" && a.loc === "亚洲");
  t("真实区码 AS 决定 SNI", a.host === "as0.sec-tunnel.com");
  t("port 取 ports[0]", a.port === 443);
  t("缺 geo 字段回落请求码 EU", b.tag === "欧洲1" && b.loc === "欧洲" && b.host === "eu0.sec-tunnel.com");
}

// counters 跨区共享序号，tag/SNI 不打架
{
  const disc1 = { return_code: { "0": "OK" }, data: { ips: [{ ip: "1.1.1.1", geo: { country_code: "AS" }, ports: [443] }] } };
  const disc2 = { return_code: { "0": "OK" }, data: { ips: [{ ip: "2.2.2.2", geo: { country_code: "AS" }, ports: [443] }] } };
  const c = {};
  const [l1] = landingsFromDisco(disc1, "AS", c);
  const [l2] = landingsFromDisco(disc2, "EU", c);
  t("第二个 AS 序号续上", l2.tag === "亚洲2" && l2.host === "as1.sec-tunnel.com");
  t("第一个仍亚洲1", l1.tag === "亚洲1" && l1.host === "as0.sec-tunnel.com");
}

// discover 错误（return_code 801）不产出落地
{
  const bad = { return_code: { "801": "No Available Proxies for Region" }, data: {} };
  const ok = { return_code: { "0": "OK" }, data: { ips: [{ ip: "3.3.3.3", geo: { country_code: "EU" }, ports: [443] }] } };
  const c = {};
  t("非 0 return_code 产出 0 条", landingsFromDisco(bad, "AS", c).length === 0);
  t("正常区仍产出", landingsFromDisco(ok, "AS", c).length === 1);
}

// landingGeo 解析健壮：空/非对象/非字符串都返回 ""
t("landingGeo 空对象", landingGeo({}) === "");
t("landingGeo 小写", landingGeo({ geo: { country_code: "eu" } }) === "EU");
t("landingGeo 非对象 geo 不炸", landingGeo({ geo: "x" }) === "");

t("REGIONS 仍三区", Object.keys(REGIONS).join(",") === "AS,EU,AM");

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);