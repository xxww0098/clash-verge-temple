// 1. 静态节点与家宽 IP 定义
const staticProxy = {
  name: "🏠 家宽住宅IP",
  type: "socks5",
  server: "您的住宅IP",
  port: 443,
  username: "用户名",
  password: "密码",
  udp: true,
  "dialer-proxy": "JP 优选" 
};

// 2. 规则集配置
const ruleProviders = {
  openai: getProv("OpenAI"),
  claude: getProv("Claude"),
  gemini: getProv("Gemini"),
  crypto: getProv("Crypto"),
  telegram: getProv("Telegram"),
  twitter: getProv("Twitter"),
  google: getProv("Google"),
  youtube: getProv("YouTube"),
  microsoft: getProv("Microsoft"),
  apple: getProv("Apple"),
  bilibili: getProv("Bilibili") 
};

function getProv(name) {
  return {
    type: "http",
    format: "yaml",
    interval: 86400,
    behavior: "classical",
    url: `https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/${name}/${name}.yaml`,
    path: `./ruleset/${name}.yaml`
  };
}

// 3. 核心规则
const mergeRules = [
  // --- 💰 加密市场 ---
  "DOMAIN-SUFFIX,polymarket.com,💰 加密市场",
  "DOMAIN-KEYWORD,polymarket,💰 加密市场",
  "DOMAIN-KEYWORD,binance,💰 加密市场",
  "DOMAIN-KEYWORD,bnbstatic,💰 加密市场",
  "DOMAIN-KEYWORD,metamask,💰 加密市场",
  "DOMAIN-SUFFIX,infura.io,💰 加密市场",
  "DOMAIN-SUFFIX,alchemy.com,💰 加密市场",
  "DOMAIN-SUFFIX,walletconnect.org,💰 加密市场",
  "DOMAIN-SUFFIX,magic.link,💰 加密市场",
  "DOMAIN-SUFFIX,moonpay.com,💰 加密市场",
  "RULE-SET,crypto,💰 加密市场",

  // --- 🤖 AI 助手 ---
  "DOMAIN-SUFFIX,grok.com,🤖 AI助手",
  "DOMAIN-SUFFIX,x.ai,🤖 AI助手",
  "DOMAIN-SUFFIX,opencode.ai,🤖 AI助手",
  "DOMAIN-SUFFIX,exa.ai,🤖 AI助手",      
  "DOMAIN-SUFFIX,context7.com,🤖 AI助手",
  
  "RULE-SET,openai,🤖 AI助手",
  "RULE-SET,claude,🤖 AI助手",
  "RULE-SET,gemini,🤖 AI助手",
  "DOMAIN-SUFFIX,chatgpt.com,🤖 AI助手",

  // --- 💬 通讯社交 ---
  "RULE-SET,twitter,💬 通讯社交",
  "DOMAIN-SUFFIX,x.com,💬 通讯社交",
  "DOMAIN-SUFFIX,twitter.com,💬 通讯社交",
  "DOMAIN-SUFFIX,t.co,💬 通讯社交",
  
  "DOMAIN-SUFFIX,facebook.com,💬 通讯社交",
  "DOMAIN-SUFFIX,instagram.com,💬 通讯社交",
  "DOMAIN-SUFFIX,fbcdn.net,💬 通讯社交",
  "DOMAIN-SUFFIX,cdninstagram.com,💬 通讯社交",
  "DOMAIN-SUFFIX,meta.com,💬 通讯社交",

  "DOMAIN-SUFFIX,discord.com,💬 通讯社交",
  "DOMAIN-SUFFIX,discordapp.com,💬 通讯社交",
  "DOMAIN-SUFFIX,discord.gg,💬 通讯社交",

  "RULE-SET,telegram,Telegram",

  // --- 流媒体与大厂 ---
  "RULE-SET,youtube,YouTube",
  "RULE-SET,google,Google",
  "RULE-SET,microsoft,Microsoft",
  "RULE-SET,apple,Apple",

  // --- 漏网之鱼与开发工具 ---
  "DOMAIN-SUFFIX,github.com,🐱 GitHub",
  "DOMAIN-SUFFIX,githubusercontent.com,🐱 GitHub",
  "DOMAIN-SUFFIX,grep.app,🐱 GitHub", 

  // --- 国内分流 ---
  "RULE-SET,bilibili,📺 哔哩哔哩",
  "GEOIP,CN,🇨🇳 国内流量",
  
  // --- 兜底 ---
  "MATCH,Final"
];

function main(config) {
  const proxies = config.proxies || [];
  const allNames = proxies
    .filter(p => p.name !== staticProxy.name && !/Traffic|Expire|流量|套餐|官网|到期/i.test(p.name))
    .map(p => p.name);

  const filter = re => allNames.filter(n => re.test(n));
  
  // 节点提取
  const hkNodes = filter(/香港|HK|Hong Kong|🇭🇰/i);
  const jpNodes = filter(/日本|JP|Japan|🇯🇵/i);
  const twNodes = filter(/台湾|TW|Taiwan|🇨🇳/i); 
  const usNodes = filter(/美国|USA|United States|🇺🇸|\bUS\b/i);
  const sgNodes = filter(/新加坡|SG|Singapore|🇸🇬/i);

  const TEST_URL = "http://www.gstatic.com/generate_204";

  // --- 定义通用列表 ---
  const regionGroups = ["HK 优选", "JP 优选", "TW 优选", "SG 优选", "US 优选"];
  
  // 1. 普通列表
  const fullProxies = ["⚡ 自动优选测速", staticProxy.name, ...regionGroups];
  
  // 2. 家宽优先列表
  const homeFirstProxies = [staticProxy.name, "⚡ 自动优选测速", ...regionGroups];

  // 3. 兜底列表
  const finalProxies = ["⚡ 自动优选测速", staticProxy.name, ...regionGroups, "DIRECT"];

  // 4. 构建策略组
  const proxyGroups = [
    { name: "⚡ 自动优选测速", type: "url-test", proxies: allNames.length > 0 ? allNames : ["DIRECT"], url: TEST_URL, interval: 300, tolerance: 50 },
    
    // --- 核心业务 (走日本家宽) ---
    { name: "💰 加密市场", type: "select", proxies: homeFirstProxies }, 
    { name: "💬 通讯社交", type: "select", proxies: homeFirstProxies },
    
    // --- 其他业务 ---
    { name: "🤖 AI助手", type: "select", proxies: fullProxies },
    { name: "🐱 GitHub", type: "select", proxies: fullProxies },
    
    // --- 常用软件 ---
    { name: "Telegram", type: "select", proxies: fullProxies },
    { name: "YouTube", type: "select", proxies: fullProxies },
    { name: "Google", type: "select", proxies: fullProxies },
    { name: "Microsoft", type: "select", proxies: ["DIRECT", ...fullProxies] },
    { name: "Apple", type: "select", proxies: ["DIRECT", ...fullProxies] },

    // --- 灵活组 ---
    { name: "📺 哔哩哔哩", type: "select", proxies: ["DIRECT", ...regionGroups] },
    { name: "🇨🇳 国内流量", type: "select", proxies: ["DIRECT", "⚡ 自动优选测速"] },
    { name: "Final", type: "select", proxies: finalProxies },

    // --- 地区优选 ---
    { name: "HK 优选", type: "url-test", proxies: hkNodes.length ? hkNodes : ["⚡ 自动优选测速"], url: TEST_URL, interval: 300, tolerance: 50 },
    { name: "JP 优选", type: "url-test", proxies: jpNodes.length ? jpNodes : ["⚡ 自动优选测速"], url: TEST_URL, interval: 300, tolerance: 50 },
    { name: "TW 优选", type: "url-test", proxies: twNodes.length ? twNodes : ["⚡ 自动优选测速"], url: TEST_URL, interval: 300, tolerance: 50 },
    { name: "SG 优选", type: "url-test", proxies: sgNodes.length ? sgNodes : ["⚡ 自动优选测速"], url: TEST_URL, interval: 300, tolerance: 50 },
    { name: "US 优选", type: "url-test", proxies: usNodes.length ? usNodes : ["⚡ 自动优选测速"], url: TEST_URL, interval: 300, tolerance: 50 }
  ];

  // 5. 校验与修复
  const valid = new Set(proxyGroups.map(g => g.name));
  valid.add("DIRECT");
  valid.add("REJECT");
  valid.add("no-resolve");
  valid.add(staticProxy.name);

  const fixRule = r => {
    if (r.startsWith("MATCH,")) return "MATCH,Final";
    return r.replace(/,([^,]+)(,no-resolve)?$/, (m, target, suffix) => {
      const t = target.trim();
      return valid.has(t) ? m : `,Final${suffix || ""}`;
    });
  };

  return {
    ...config,
    proxies: [...proxies, staticProxy],
    "rule-providers": ruleProviders,
    "proxy-groups": proxyGroups,
    rules: [...mergeRules, ...(config.rules || []).map(fixRule)]
  };
}