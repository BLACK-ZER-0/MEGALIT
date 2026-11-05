

TOKENS = {
 "360 PanYun": {
  "body": [
  ],
  "cookies": [],
  "headers": [
   "360wz",
   "360pan"
  ],
  "server": [
  ],
  "type": "WAF"
 },
 "360 Wangzhan": {
  "body": [
   "360wang"
  ],
  "cookies": [],
  "headers": [
   "360wangzhanbao"
  ],
  "server": [
  ],
  "type": "WAF"
 },
 "ASP.NET": {
  "body": [
   "potentially dangerous request.form",
   "asp.net validation",
   "request validation has detected a potentially dangerous",
   "request.unvalidated",
   "requestvalidationmode"
  ],
  "cookies": [
   "asp.net_sessionid"
  ],
  "headers": [
   "x-aspnet-version",
   "x-aspnetmvc-version",
   "^x-aspnet-version",
   "^x-powered-by:.*asp.net"
  ],
  "server": [
   "asp.net"
  ],
  "type": "WAF"
 },
 "ASPA Firewall": {
  "body": [],
  "cookies": [],
  "headers": [
   "ASPA"
  ],
  "server": [
   "aspa"
  ],
  "type": "WAF"
 },
 "AWS ALB/ELB": {
  "body": [],
  "cookies": [],
  "headers": [
   "awselb",
   "amazon"
  ],
  "server": [
   "awselb",
   "amazon"
  ],
  "type": "LB"
 },
 "AWS WAF": {
  "body": [
   "request blocked by aws waf",
   "aws-waf-logs"
  ],
  "cookies": [],
  "headers": [
   "x-amz-id-2",
   "x-amz-request-id",
   "x-amzn-RequestId"
  ],
  "server": [],
  "type": "WAF"
 },
 "AireeCDN": {
  "body": [],
  "cookies": [],
  "headers": [
   "airee"
  ],
  "server": [
   "airee"
  ],
  "type": "WAF"
 },
 "Airlock (Ergon)": {
  "body": [],
  "cookies": [],
  "headers": [
   "airlock"
  ],
  "server": [
   "airlock"
  ],
  "type": "WAF"
 },
 "Akamai": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-akamai-request-id",
   "akamaighost",
   "akamaicdn"
  ],
  "server": [
   "akamai",
   "kona"
  ],
  "type": "CDN"
 },
 "Alert Logic": {
  "body": [],
  "cookies": [],
  "headers": [
   "alertlogic",
   "x-alertlogic"
  ],
  "server": [
   "alertlogic"
  ],
  "type": "WAF"
 },
 "AliYunDun": {
  "body": [],
  "cookies": [],
  "headers": [
   "aliyun",
   "yundun"
  ],
  "server": [
   "aliyun",
   "yundun"
  ],
  "type": "WAF"
 },
 "Alibaba CDN": {
  "body": [],
  "cookies": [
   "acw_tc",
   "cdn_sec_tc"
  ],
  "headers": [],
  "server": [],
  "type": "CDN"
 },
 "Alibaba Cloud": {
  "body": [],
  "cookies": [],
  "headers": [
   "server: tengine"
  ],
  "server": [],
  "type": "LB"
 },
 "Aliyun WAF": {
  "body": [
   "访问被禁止",
   "阿里云web应用防火墙"
  ],
  "cookies": [
   "acw_tc",
   "cdn_sec_tc"
  ],
  "headers": [],
  "server": [],
  "type": "WAF"
 },
 "AnYu": {
  "body": [],
  "cookies": [],
  "headers": [
   "anyu"
  ],
  "server": [
   "anyu"
  ],
  "type": "WAF"
 },
 "AnYu / Anquanbao / Anubis": {
  "body": [
   "anquanbao",
   "安全宝",
   "anubis"
  ],
  "cookies": [
   "anquanbao"
  ],
  "headers": [
   "server: anyu",
   "x-anquanbao"
  ],
  "server": [],
  "type": "WAF"
 },
 "Anquanbao": {
  "body": [],
  "cookies": [],
  "headers": [
   "anquanbao"
  ],
  "server": [
   "anquanbao"
  ],
  "type": "WAF"
 },
 "AppWall": {
  "body": [],
  "cookies": [],
  "headers": [
   "appwall",
   "radware"
  ],
  "server": [
   "radware"
  ],
  "type": "WAF"
 },
 "Armor Defense": {
  "body": [
   "armor defense",
  ],
  "cookies": [],
  "headers": [
   "x-armor",
   "armor"
  ],
  "server": [
   "armor"
  ],
  "type": "WAF"
 },
 "ArvanCloud": {
  "body": [],
  "cookies": [],
  "headers": [
   "arvan"
  ],
  "server": [
   "arvan"
  ],
  "type": "WAF"
 },
 "Astra": {
  "body": [],
  "cookies": [],
  "headers": [
   "astra"
  ],
  "server": [
   "astra"
  ],
  "type": "WAF"
 },
 "Azion": {
  "body": [],
  "cookies": [],
  "headers": [
   "azion"
  ],
  "server": [
   "azion"
  ],
  "type": "WAF"
 },
 "Azure Application Gateway": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-arr-ssl",
   "x-arr-log-id"
  ],
  "server": [
   "azure"
  ],
  "type": "WAF"
 },
 "Azure Front Door/CDN": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-arr-log-id",
   "x-msedge-ref",
   "x-azure-ref",
   "x-fd-id"
  ],
  "server": [
   "azure",
   "msedge"
  ],
  "type": "CDN"
 },
 "BIG-IP": {
  "body": [],
  "cookies": [
   "BIGipServer"
  ],
  "headers": [
   "bigip",
   "BIG-IP"
  ],
  "server": [
   "bigip",
  ],
  "type": "WAF"
 },
 "Baffin Bay (Mastercard)": {
  "body": [],
  "cookies": [],
  "headers": [
   "baffin"
  ],
  "server": [
   "baffin"
  ],
  "type": "WAF"
 },
 "Baidu Cloud (BCE)": {
  "body": [],
  "cookies": [],
  "headers": [
   "baidu",
   "x-bce-"
  ],
  "server": [
   "baidu",
  ],
  "type": "WAF"
 },
 "Baidu Yunjiasu": {
  "body": [],
  "cookies": [],
  "headers": [
   "yunjiasu"
  ],
  "server": [
   "yunjiasu"
  ],
  "type": "CDN"
 },
 "Barikode": {
  "body": [],
  "cookies": [],
  "headers": [
   "barikode"
  ],
  "server": [
   "barikode"
  ],
  "type": "WAF"
 },
 "Barracuda": {
  "body": [],
  "cookies": [],
  "headers": [
   "barracuda",
   "x-barracuda",
   "netcontinuum"
  ],
  "server": [
   "barracuda",
   "netcontinuum"
  ],
  "type": "WAF"
 },
 "Bekchy": {
  "body": [],
  "cookies": [],
  "headers": [
   "bekchy"
  ],
  "server": [
   "bekchy"
  ],
  "type": "WAF"
 },
 "Bekchy / Beluga CDN": {
  "body": [],
  "cookies": [
   "bekchy"
  ],
  "headers": [
   "x-bekchy",
   "server: beluga"
  ],
  "server": [],
  "type": "CDN/WAF"
 },
 "BelugaCDN": {
  "body": [],
  "cookies": [],
  "headers": [
   "belugacdn"
  ],
  "server": [
   "beluga",
   "belugacdn"
  ],
  "type": "WAF"
 },
 "BinarySec": {
  "body": [],
  "cookies": [],
  "headers": [
   "binarysec"
  ],
  "server": [
   "binarysec"
  ],
  "type": "WAF"
 },
 "BinarySec / BitNinja": {
  "body": [
   "bitninja",
   "interception"
  ],
  "cookies": [
   "bn_"
  ],
  "headers": [
   "x-binarysec-via",
   "x-bitninja"
  ],
  "server": [],
  "type": "WAF"
 },
 "BitNinja": {
  "body": [],
  "cookies": [],
  "headers": [
   "bitninja"
  ],
  "server": [
   "bitninja"
  ],
  "type": "WAF"
 },
 "BlockDoS": {
  "body": [],
  "cookies": [],
  "headers": [
   "blockdos"
  ],
  "server": [
   "blockdos"
  ],
  "type": "WAF"
 },
 "BlockDoS / Bluedon": {
  "body": [
   "bluedon",
   "blockdos"
  ],
  "cookies": [],
  "headers": [
   "server: bluedon"
  ],
  "server": [],
  "type": "WAF"
 },
 "Bluedon": {
  "body": [],
  "cookies": [],
  "headers": [
   "bluedon"
  ],
  "server": [
   "bluedon"
  ],
  "type": "WAF"
 },
 "BulletProof Security": {
  "body": [],
  "cookies": [],
  "headers": [
   "bulletproof"
  ],
  "server": [
   "bulletproof"
  ],
  "type": "WAF"
 },
 "CDN77": {
  "body": [],
  "cookies": [],
  "headers": [
   "cdn77"
  ],
  "server": [
   "cdn77"
  ],
  "type": "WAF"
 },
 "CacheFly": {
  "body": [],
  "cookies": [],
  "headers": [
   "cachefly"
  ],
  "server": [
   "cachefly"
  ],
  "type": "WAF"
 },
 "CacheFly CDN / CacheWall": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-cachefly",
   "x-varnish",
   "x-hw"
  ],
  "server": [],
  "type": "CDN"
 },
 "CacheWall": {
  "body": [],
  "cookies": [],
  "headers": [
   "cachewall",
   "varnish"
  ],
  "server": [
   "cachewall",
   "varnish"
  ],
  "type": "WAF"
 },
 "CdnNS Gateway": {
  "body": [
   "cdnns"
  ],
  "cookies": [],
  "headers": [
   "server: cdnns"
  ],
  "server": [],
  "type": "CDN/WAF"
 },
 "ChinaCache": {
  "body": [],
  "cookies": [],
  "headers": [
   "chinacache",
  ],
  "server": [
   "chinacache"
  ],
  "type": "WAF"
 },
 "Cisco ACE XML Gateway": {
  "body": [],
  "cookies": [],
  "headers": [
   "ACE XML Gateway",
   "ACE-XML"
  ],
  "server": [
  ],
  "type": "LB"
 },
 "Cloud Protector": {
  "body": [],
  "cookies": [],
  "headers": [
   "cloud-protector",
   "denyal"
  ],
  "server": [
   "cloud-protector"
  ],
  "type": "WAF"
 },
 "Cloudbric": {
  "body": [],
  "cookies": [],
  "headers": [
   "cloudbric"
  ],
  "server": [
   "cloudbric"
  ],
  "type": "WAF"
 },
 "Cloudbric / Cloudfloor": {
  "body": [
   "cloudbric"
  ],
  "cookies": [
   "cloudbric_session"
  ],
  "headers": [
   "x-cloudbric"
  ],
  "server": [],
  "type": "WAF"
 },
 "Cloudflare": {
  "body": [
   "Cloudflare Ray ID"
  ],
  "cookies": [
   "__cfduid"
  ],
  "headers": [
   "cf-ray",
   "cf-cache-status",
   "server:.*cloudflare"
  ],
  "server": [
   "cloudflare"
  ],
  "type": "WAF"
 },
 "Cloudfloor": {
  "body": [],
  "cookies": [],
  "headers": [
   "cloudfloor"
  ],
  "server": [
   "cloudfloor"
  ],
  "type": "CDN"
 },
 "Cloudfront": {
  "body": [],
  "cookies": [],
  "headers": [
   "cloudfront",
   "x-amz-cf-id"
  ],
  "server": [
   "cloudfront",
   "awselb"
  ],
  "type": "CDN"
 },
 "Comodo WAF (cWatch)": {
  "body": [],
  "cookies": [],
  "headers": [
   "comodo",
   "cwatch"
  ],
  "server": [
   "comodo"
  ],
  "type": "WAF"
 },
 "CrawlProtect": {
  "body": [],
  "cookies": [],
  "headers": [
   "crawlprotect"
  ],
  "server": [
   "crawlprotect"
  ],
  "type": "WAF"
 },
 "DDoS-GUARD": {
  "body": [],
  "cookies": [],
  "headers": [
   "ddos-guard"
  ],
  "server": [
   "ddos-guard"
  ],
  "type": "WAF"
 },
 "DOSarrest": {
  "body": [],
  "cookies": [],
  "headers": [
   "dosarrest"
  ],
  "server": [
   "dosarrest"
  ],
  "type": "WAF"
 },
 "DataPower": {
  "body": [],
  "cookies": [],
  "headers": [
   "datapower",
   "IBM_HTTP_Server"
  ],
  "server": [
   "datapower"
  ],
  "type": "WAF"
 },
 "DenyALL": {
  "body": [],
  "cookies": [],
  "headers": [
   "denyall"
  ],
  "server": [
   "denyall"
  ],
  "type": "WAF"
 },
 "Distil": {
  "body": [],
  "cookies": [
   "distil_r_c"
  ],
  "headers": [
   "distil"
  ],
  "server": [
   "distil"
  ],
  "type": "WAF"
 },
 "Distil / DotDefender": {
  "body": [
   "dotdefender",
   "distil networks"
  ],
  "cookies": [
   "dotdefender"
  ],
  "headers": [
   "x-distil"
  ],
  "server": [],
  "type": "WAF"
 },
 "DotDefender": {
  "body": [],
  "cookies": [],
  "headers": [
   "dotdefender"
  ],
  "server": [
   "dotdefender"
  ],
  "type": "WAF"
 },
 "DynamicWeb Injection Check": {
  "body": [
   "dynamicweb injection check"
  ],
  "cookies": [],
  "headers": [],
  "server": [],
  "type": "WAF"
 },
 "EdgeCast": {
  "body": [],
  "cookies": [],
  "headers": [
   "edgecast",
  ],
  "server": [
   "edgecast"
  ],
  "type": "WAF"
 },
 "EdgeProvider_Generic": {
  "body": [],
  "cookies": [],
  "headers": [
   "cdn|edge|akamai|fastly|cloudflare|stackpath|cloudfront"
  ],
  "server": [
   "cdn",
   "edge"
  ],
  "type": "CDN"
 },
 "Edgecast": {
  "body": [],
  "cookies": [],
  "headers": [
   "edgecast",
   "^server:.*ECS"
  ],
  "server": [
   "edgecast"
  ],
  "type": "WAF"
 },
 "Eisoo Cloud Firewall": {
  "body": [],
  "cookies": [],
  "headers": [
   "eisoo"
  ],
  "server": [
   "eisoo"
  ],
  "type": "WAF"
 },
 "Envoy": {
  "body": [],
  "cookies": [],
  "headers": [
   "envoy"
  ],
  "server": [
   "envoy"
  ],
  "type": "WAF"
 },
 "Envoy / Expression Engine": {
  "body": [
   "expressionengine"
  ],
  "cookies": [],
  "headers": [
   "x-envoy-upstream-service-time"
  ],
  "server": [],
  "type": "LB/WAF"
 },
 "ExpressionEngine": {
  "body": [],
  "cookies": [],
  "headers": [
   "expressionengine"
  ],
  "server": [
   "expressionengine"
  ],
  "type": "WAF"
 },
 "F5 BIG-IP ASM": {
  "body": [
   "Request blocked by F5",
   "BIGIP"
  ],
  "cookies": [
   "BIGipServer"
  ],
  "headers": [
   "x-waf-.*",
   "x-iinfo",
   "^server:.*bigip"
  ],
  "server": [
   "bigip",
  ],
  "type": "WAF"
 },
 "F5 BIG-IP LTM": {
  "body": [],
  "cookies": [
   "BIGipServer"
  ],
  "headers": [
   "x-iinfo",
   "bigip",
   "BIG-IP"
  ],
  "server": [
   "bigip",
  ],
  "type": "LB"
 },
 "F5 FirePass": {
  "body": [],
  "cookies": [],
  "headers": [
   "firepass"
  ],
  "server": [
   "firepass"
  ],
  "type": "WAF"
 },
 "F5 TrafficShield": {
  "body": [],
  "cookies": [],
  "headers": [
   "trafficshield"
  ],
  "server": [
   "trafficshield"
  ],
  "type": "WAF"
 },
 "Fastly": {
  "body": [],
  "cookies": [],
  "headers": [
   "fastly",
   "x-served-by"
  ],
  "server": [
   "fastly"
  ],
  "type": "CDN"
 },
 "FortiWeb": {
  "body": [],
  "cookies": [],
  "headers": [
   "fortiweb",
   "x-forti-"
  ],
  "server": [
   "fortiweb",
   "fortinet"
  ],
  "type": "WAF"
 },
 "GoDaddy WAF": {
  "body": [],
  "cookies": [],
  "headers": [
   "GoDaddy-Web-Application-Protection",
  ],
  "server": [
   "godaddy"
  ],
  "type": "WAF"
 },
 "Google Cloud Armor": {
  "body": [],
  "cookies": [],
  "headers": [
   "google",
   "gws"
  ],
  "server": [
   "google"
  ],
  "type": "WAF"
 },
 "Grey Wizard": {
  "body": [
   "hyperguard"
  ],
  "cookies": [],
  "headers": [
   "x-greywizard",
   "greywizard"
  ],
  "server": [
   "greywizard"
  ],
  "type": "WAF"
 },
 "Highwinds": {
  "body": [],
  "cookies": [],
  "headers": [
   "highwinds"
  ],
  "server": [
   "highwinds"
  ],
  "type": "WAF"
 },
 "Huawei Cloud WAF": {
  "body": [],
  "cookies": [],
  "headers": [
   "huawei"
  ],
  "server": [
   "huawei"
  ],
  "type": "WAF"
 },
 "HyperGuard (Art of Defense)": {
  "body": [],
  "cookies": [],
  "headers": [
   "hyperguard"
  ],
  "server": [
   "hyperguard"
  ],
  "type": "WAF"
 },
 "Imperva (Incapsula)": {
  "body": [
   "Incapsula incident ID"
  ],
  "cookies": [
   "incap_ses_"
  ],
  "headers": [
   "incapsula",
   "X-Iinfo",
   "x-cdn",
   "visid_incap"
  ],
  "server": [
   "incapsula",
   "imperva"
  ],
  "type": "WAF"
 },
 "Imperva / Incapsula": {
  "body": [
   "Incapsula incident ID",
   "Access Denied - Incapsula"
  ],
  "cookies": [
   "incap_ses_",
   "visid_"
  ],
  "headers": [
   "^server:.*incapsula",
   "x-cdn:.*incapsula",
   "x-im-perf"
  ],
  "server": [
   "incapsula",
   "imperva"
  ],
  "type": "WAF"
 },
 "Imunify360": {
  "body": [],
  "cookies": [],
  "headers": [
   "imunify",
   "imunify360"
  ],
  "server": [
   "imunify"
  ],
  "type": "WAF"
 },
 "Incapsula": {
  "body": [],
  "cookies": [
   "incap_ses",
   "visid_incap"
  ],
  "headers": [
   "incapsula",
   "incap_ses",
   "visid_incap"
  ],
  "server": [
   "incapsula"
  ],
  "type": "WAF"
 },
 "IndusGuard": {
  "body": [],
  "cookies": [],
  "headers": [
   "indusguard",
   "indusface"
  ],
  "server": [
   "indusguard"
  ],
  "type": "WAF"
 },
 "IndusGuard / Instart DX": {
  "body": [],
  "cookies": [
   "instart"
  ],
  "headers": [
   "x-iinfo",
   "x-instart-request-id"
  ],
  "server": [],
  "type": "WAF/CDN"
 },
 "Instart Logic": {
  "body": [],
  "cookies": [],
  "headers": [
   "instart"
  ],
  "server": [
   "instart"
  ],
  "type": "WAF"
 },
 "Janusec": {
  "body": [
   "janusec"
  ],
  "cookies": [
   "janusec"
  ],
  "headers": [
   "server: janusec",
   "x-janusec",
   "janusec"
  ],
  "server": [
   "janusec"
  ],
  "type": "WAF"
 },
 "JiaShiLe (加速乐)": {
  "body": [],
  "cookies": [],
  "headers": [
   "jiasule"
  ],
  "server": [
   "jiasule"
  ],
  "type": "WAF"
 },
 "KS-WAF (KnownSec)": {
  "body": [],
  "cookies": [],
  "headers": [
   "knownsec",
   "ks-waf"
  ],
  "server": [
   "knownsec"
  ],
  "type": "WAF"
 },
 "Kemp LoadMaster": {
  "body": [],
  "cookies": [],
  "headers": [
   "loadmaster",
   "kemp"
  ],
  "server": [
   "kemp"
  ],
  "type": "WAF"
 },
 "KeyCDN": {
  "body": [],
  "cookies": [],
  "headers": [
   "keycdn"
  ],
  "server": [
   "keycdn"
  ],
  "type": "WAF"
 },
 "Kona SiteDefender": {
  "body": [],
  "cookies": [],
  "headers": [
   "kona",
   "kona-*"
  ],
  "server": [
   "kona"
  ],
  "type": "WAF"
 },
 "Link11": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-link11-waap"
  ],
  "server": [],
  "type": "WAF"
 },
 "LiteSpeed": {
  "body": [],
  "cookies": [],
  "headers": [
   "litespeed"
  ],
  "server": [
   "litespeed"
  ],
  "type": "WAF"
 },
 "Malcare": {
  "body": [],
  "cookies": [],
  "headers": [
   "malcare"
  ],
  "server": [
   "malcare"
  ],
  "type": "WAF"
 },
 "Malcare / Mission Control Shield": {
  "body": [
   "malcare",
   "mission control shield"
  ],
  "cookies": [],
  "headers": [],
  "server": [],
  "type": "WAF"
 },
 "MaxCDN": {
  "body": [],
  "cookies": [],
  "headers": [
   "maxcdn"
  ],
  "server": [
   "maxcdn"
  ],
  "type": "WAF"
 },
 "Microsoft ISA / TMG": {
  "body": [],
  "cookies": [],
  "headers": [
   "isa server"
  ],
  "server": [
   "isa"
  ],
  "type": "WAF"
 },
 "ModSecurity": {
  "body": [
   "ModSecurity",
   "This request has been blocked",
  ],
  "cookies": [],
  "headers": [
   "mod_security",
   "mod_security_tomcat",
   "Mod_Security",
   "ModSecurity"
  ],
  "server": [
   "mod_security",
   "modsecurity"
  ],
  "type": "WAF"
 },
 "Myra Security": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-myra"
  ],
  "server": [
   "myra"
  ],
  "type": "WAF"
 },
 "NAXSI": {
  "body": [],
  "cookies": [],
  "headers": [
   "naxsi"
  ],
  "server": [
   "naxsi"
  ],
  "type": "WAF"
 },
 "NSFocus": {
  "body": [],
  "cookies": [],
  "headers": [
   "nsfocus"
  ],
  "server": [
   "nsfocus"
  ],
  "type": "WAF"
 },
 "Nemesida": {
  "body": [
   "nemesida"
  ],
  "cookies": [],
  "headers": [
   "x-nemesida",
   "x-netcontinuum"
  ],
  "server": [],
  "type": "WAF"
 },
 "NetScaler AppFirewall": {
  "body": [
   "transaction signature failed",
   "requested url was rejected",
   "reason:",
   "appfirewall",
   "citrix netscaler"
  ],
  "cookies": [
   "NSC_"
  ],
  "headers": [
   "ns_af_ver",
   "ns_af_typ",
   "ns_server",
   "citrix_ns_id"
  ],
  "server": [],
  "type": "WAF"
 },
 "NetShield": {
  "body": [
   "netshield"
  ],
  "cookies": [],
  "headers": [
   "netshield"
  ],
  "server": [
   "netshield"
  ],
  "type": "WAF"
 },
 "Newdefend": {
  "body": [
   "newdefend"
  ],
  "cookies": [],
  "headers": [
   "x-nevis-proxy"
  ],
  "server": [],
  "type": "WAF"
 },
 "NexusGuard": {
  "body": [
   "nullddos"
  ],
  "cookies": [],
  "headers": [
   "x-nexusguard",
   "nexusguard"
  ],
  "server": [
   "nexusguard"
  ],
  "type": "CDN/WAF"
 },
 "NinjaFirewall": {
  "body": [],
  "cookies": [],
  "headers": [
   "ninjafirewall"
  ],
  "server": [
   "ninjafirewall"
  ],
  "type": "WAF"
 },
 "NullDDoS": {
  "body": [
   "nullddos"
  ],
  "cookies": [],
  "headers": [
   "nullddos"
  ],
  "server": [
   "nullddos"
  ],
  "type": "WAF"
 },
 "OnMessage Shield (Blackbaud)": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-blackbaud-shield"
  ],
  "server": [],
  "type": "WAF"
 },
 "OpenResty": {
  "body": [],
  "cookies": [],
  "headers": [
   "openresty",
  ],
  "server": [
   "openresty",
  ],
  "type": "WAF"
 },
 "Oracle Cloud": {
  "body": [],
  "cookies": [],
  "headers": [
   "oracle",
   "ocid"
  ],
  "server": [
   "oracle"
  ],
  "type": "WAF"
 },
 "Palo Alto Networks": {
  "body": [],
  "cookies": [],
  "headers": [
   "paloalto",
   "pan-"
  ],
  "server": [
   "paloalto"
  ],
  "type": "WAF"
 },
 "PentaWAF / PerimeterX": {
  "body": [
   "perimeterx"
  ],
  "cookies": [
   "_px",
   "_pxvid"
  ],
  "headers": [
   "x-px",
   "x-perimeterx"
  ],
  "server": [],
  "type": "WAF"
 },
 "PerimeterX": {
  "body": [],
  "cookies": [
   "_px.*"
  ],
  "headers": [
   "perimeterx",
   "px-"
  ],
  "server": [
   "perimeterx"
  ],
  "type": "WAF"
 },
 "PerimeterX (HUMAN)": {
  "body": [],
  "cookies": [],
  "headers": [
   "perimeterx"
  ],
  "server": [
   "perimeterx"
  ],
  "type": "WAF"
 },
 "PowerCDN": {
  "body": [
   "puhui"
  ],
  "cookies": [
   "profense"
  ],
  "headers": [
   "server: profense",
   "x-powercdn",
   "powercdn"
  ],
  "server": [
   "powercdn"
  ],
  "type": "CDN/WAF"
 },
 "Profense": {
  "body": [],
  "cookies": [],
  "headers": [
   "profense"
  ],
  "server": [
   "profense"
  ],
  "type": "WAF"
 },
 "Qiniu": {
  "body": [],
  "cookies": [],
  "headers": [
   "qiniu"
  ],
  "server": [
   "qiniu"
  ],
  "type": "CDN"
 },
 "Qrator": {
  "body": [],
  "cookies": [],
  "headers": [
   "qrator"
  ],
  "server": [
   "qrator"
  ],
  "type": "WAF"
 },
 "RayWAF (WebRay)": {
  "body": [],
  "cookies": [],
  "headers": [
   "raywaf"
  ],
  "server": [
   "raywaf"
  ],
  "type": "WAF"
 },
 "RayWAF / Reblaze": {
  "body": [
   "reblaze"
  ],
  "cookies": [
   "reblaze"
  ],
  "headers": [
   "x-raywaf",
   "server: reblaze"
  ],
  "server": [],
  "type": "WAF"
 },
 "Reblaze": {
  "body": [],
  "cookies": [],
  "headers": [
   "reblaze"
  ],
  "server": [
   "reblaze"
  ],
  "type": "WAF"
 },
 "Reflected Networks": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-reflected-networks"
  ],
  "server": [],
  "type": "CDN/WAF"
 },
 "SEnginx / Sabre / Safe3": {
  "body": [
   "sabre",
   "safe3"
  ],
  "cookies": [],
  "headers": [
   "server: senginx",
   "server: safe3web"
  ],
  "server": [],
  "type": "WAF"
 },
 "Safe3": {
  "body": [
   "safe3"
  ],
  "cookies": [],
  "headers": [
   "safe3",
   "safe3waf"
  ],
  "server": [
   "safe3"
  ],
  "type": "WAF"
 },
 "SafeDog": {
  "body": [
   "safedog"
  ],
  "cookies": [],
  "headers": [
   "safedog"
  ],
  "server": [
   "safedog"
  ],
  "type": "WAF"
 },
 "Scutum / SecKing": {
  "body": [
   "scutum",
   "secking"
  ],
  "cookies": [],
  "headers": [
   "server: secking"
  ],
  "server": [],
  "type": "WAF"
 },
 "SecuPress": {
  "body": [
   "secupress",
   "secure entry"
  ],
  "cookies": [],
  "headers": [],
  "server": [],
  "type": "WAF"
 },
 "SecuPress WP Security": {
  "body": [],
  "cookies": [],
  "headers": [
   "secupress"
  ],
  "server": [
   "secupress"
  ],
  "type": "WAF"
 },
 "SecureIIS (eEye)": {
  "body": [
   "secureiis"
  ],
  "cookies": [],
  "headers": [
   "server: secureiis"
  ],
  "server": [],
  "type": "WAF"
 },
 "SecureSphere (Imperva)": {
  "body": [],
  "cookies": [],
  "headers": [
   "securesphere"
  ],
  "server": [
   "securesphere"
  ],
  "type": "WAF"
 },
 "ServerDefender (Port80)": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-serverdefender"
  ],
  "server": [],
  "type": "WAF"
 },
 "Shadow Daemon": {
  "body": [],
  "cookies": [],
  "headers": [
   "shadow daemon",
   "shadowdaemon"
  ],
  "server": [
   "shadowdaemon"
  ],
  "type": "WAF"
 },
 "Shieldon": {
  "body": [
   "shield security",
   "shieldon"
  ],
  "cookies": [],
  "headers": [
   "shieldon",
   "shield"
  ],
  "server": [
   "shieldon",
   "shield"
  ],
  "type": "WAF"
 },
 "SiteGround": {
  "body": [],
  "cookies": [],
  "headers": [
   "siteground"
  ],
  "server": [
   "siteground"
  ],
  "type": "WAF"
 },
 "SiteGround / SiteGuard": {
  "body": [
   "siteguard"
  ],
  "cookies": [],
  "headers": [
   "server: siteground"
  ],
  "server": [],
  "type": "WAF"
 },
 "SiteGuard": {
  "body": [],
  "cookies": [],
  "headers": [
   "siteguard"
  ],
  "server": [
   "siteguard"
  ],
  "type": "WAF"
 },
 "SiteLock": {
  "body": [],
  "cookies": [],
  "headers": [
   "sitelock",
   "trueshield"
  ],
  "server": [
   "sitelock",
   "trueshield"
  ],
  "type": "WAF"
 },
 "SonicWall": {
  "body": [],
  "cookies": [],
  "headers": [
   "sonicwall"
  ],
  "server": [
   "sonicwall"
  ],
  "type": "WAF"
 },
 "Sophos UTM": {
  "body": [
   "sophos utm"
  ],
  "cookies": [],
  "headers": [
   "server: sophos"
  ],
  "server": [],
  "type": "WAF"
 },
 "Squarespace / SquidProxy": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-squarespace",
   "x-squid-error"
  ],
  "server": [],
  "type": "CDN/WAF"
 },
 "Squid": {
  "body": [
   "squid"
  ],
  "cookies": [],
  "headers": [
   "squid",
   "x-squid"
  ],
  "server": [
   "squid"
  ],
  "type": "WAF"
 },
 "StackPath": {
  "body": [],
  "cookies": [],
  "headers": [
   "stackpath"
  ],
  "server": [
   "stackpath"
  ],
  "type": "WAF"
 },
 "Sucuri": {
  "body": [],
  "cookies": [
   "sucuri_cloudproxy_uuid"
  ],
  "headers": [
   "x-sucuri-id",
   "sucuri",
   "sucuri_cloudproxy"
  ],
  "server": [
   "sucuri"
  ],
  "type": "WAF"
 },
 "Tencent Cloud": {
  "body": [],
  "cookies": [],
  "headers": [
   "qcloud",
   "qcloudcdn",
   "yunjiasu",
   "tencent"
  ],
  "server": [
   "qcloud",
   "tencent",
   "yunjiasu"
  ],
  "type": "WAF"
 },
 "Tencent WAF": {
  "body": [],
  "cookies": [],
  "headers": [
   "tencent",
   "tencentcdn"
  ],
  "server": [
   "tencent"
  ],
  "type": "WAF"
 },
 "ThreatX": {
  "body": [
   "threatx"
  ],
  "cookies": [],
  "headers": [
   "x-teros",
   "x-threatx",
   "threatx"
  ],
  "server": [
   "threatx"
  ],
  "type": "WAF"
 },
 "TransIP Web Firewall": {
  "body": [
   "transip web firewall"
  ],
  "cookies": [],
  "headers": [
   "server: transip-web-firewall"
  ],
  "server": [],
  "type": "WAF"
 },
 "UEWaf (UCloud)": {
  "body": [
   "urlscan",
   "rejected-by-urlscan"
  ],
  "cookies": [],
  "headers": [
   "x-uewaf"
  ],
  "server": [],
  "type": "WAF"
 },
 "Variti": {
  "body": [],
  "cookies": [],
  "headers": [
   "variti"
  ],
  "server": [
   "variti"
  ],
  "type": "WAF"
 },
 "Varnish": {
  "body": [],
  "cookies": [],
  "headers": [
   "varnish"
  ],
  "server": [
   "varnish"
  ],
  "type": "WAF"
 },
 "Viettel (Cloudrity)": {
  "body": [
   "virusdie",
   "viettel"
  ],
  "cookies": [],
  "headers": [
   "server: viettel",
   "viettel",
   "cloudrity"
  ],
  "server": [
   "viettel",
   "cloudrity"
  ],
  "type": "WAF"
 },
 "VirusDie": {
  "body": [
   "virusdie"
  ],
  "cookies": [],
  "headers": [
   "virusdie"
  ],
  "server": [
   "virusdie"
  ],
  "type": "WAF"
 },
 "WP Cerber": {
  "body": [
   "wp cerber",
   "wts-waf"
  ],
  "cookies": [
   "cerber"
  ],
  "headers": [
   "cerber"
  ],
  "server": [
   "cerber"
  ],
  "type": "WAF"
 },
 "WPMU Defender": {
  "body": [
   "pksecurity",
   "wpmudev defender"
  ],
  "cookies": [],
  "headers": [],
  "server": [],
  "type": "WAF"
 },
 "Wallarm": {
  "body": [],
  "cookies": [],
  "headers": [
   "nginx-wallarm",
   "wallarm"
  ],
  "server": [
   "wallarm"
  ],
  "type": "WAF"
 },
 "WatchGuard": {
  "body": [],
  "cookies": [],
  "headers": [
   "watchguard"
  ],
  "server": [
   "watchguard"
  ],
  "type": "WAF"
 },
 "WebARX": {
  "body": [
   "webarx"
  ],
  "cookies": [
   "warx"
  ],
  "headers": [
   "x-warx",
   "webarx"
  ],
  "server": [
   "webarx"
  ],
  "type": "WAF"
 },
 "WebKnight": {
  "body": [],
  "cookies": [],
  "headers": [
   "webknight"
  ],
  "server": [
   "webknight"
  ],
  "type": "WAF"
 },
 "WebSEAL (IBM)": {
  "body": [],
  "cookies": [],
  "headers": [
   "webseal"
  ],
  "server": [
   "webseal"
  ],
  "type": "WAF"
 },
 "WebTotem": {
  "body": [
   "west263"
  ],
  "cookies": [],
  "headers": [
   "x-webtotem"
  ],
  "server": [],
  "type": "CDN/WAF"
 },
 "WordPress": {
  "body": [],
  "cookies": [],
  "headers": [
   "wp-cerber|wordfence|secupress|sucuri"
  ],
  "server": [
   "wordpress"
  ],
  "type": "WAF"
 },
 "Wordfence": {
  "body": [
   "Wordfence"
  ],
  "cookies": [
   "wordpress_logged_in"
  ],
  "headers": [
   "wordfence"
  ],
  "server": [
   "wordfence"
  ],
  "type": "WAF"
 },
 "XLabs Security WAF": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-xlabs-waf"
  ],
  "server": [],
  "type": "WAF"
 },
 "Xuanwudun / YXLink": {
  "body": [
   "xuanwudun"
  ],
  "cookies": [],
  "headers": [
   "server: yxlink"
  ],
  "server": [],
  "type": "WAF"
 },
 "Yunsuo (云锁)": {
  "body": [
   "云锁",
   "yunsuo"
  ],
  "cookies": [
   "yunsuo_session"
  ],
  "headers": [
   "x-yunjiasu",
   "server: yunsuo",
   "yunsuo"
  ],
  "server": [
   "yunsuo"
  ],
  "type": "WAF"
 },
 "ZenEdge": {
  "body": [],
  "cookies": [],
  "headers": [
   "x-zen-edge"
  ],
  "server": [
   "zenedge"
  ],
  "type": "WAF"
 },
 "Zenedge": {
  "body": [
   "aesecure"
  ],
  "cookies": [],
  "headers": [
   "x-zenedge",
   "zenedge"
  ],
  "server": [
   "zenedge"
  ],
  "type": "WAF"
 },
 "Zscaler": {
  "body": [],
  "cookies": [],
  "headers": [
   "zscaler",
   "x-zscaler"
  ],
  "server": [
   "zscaler"
  ],
  "type": "WAF"
 },
 "aeSecure": {
  "body": [
   "aesecure"
  ],
  "cookies": [],
  "headers": [
   "aesecure"
  ],
  "server": [
   "aesecure"
  ],
  "type": "WAF"
 }
}
