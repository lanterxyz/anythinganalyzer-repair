import { readFileSync } from "fs";
import type { CaManager } from "./ca-manager";

/** Magic hostname that triggers the cert download page */
export const CERT_DOWNLOAD_HOST = "cert.anything.test";
export const CERT_DOWNLOAD_FALLBACK_HOST = "cert.anything.local";

export function isCertDownloadHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  return normalized === CERT_DOWNLOAD_HOST || normalized === CERT_DOWNLOAD_FALLBACK_HOST;
}

/**
 * Detect platform from User-Agent string.
 */
function detectPlatform(ua: string): "ios" | "android" | "desktop" {
  if (/iPhone|iPad|iPod/i.test(ua)) return "ios";
  if (/Android/i.test(ua)) return "android";
  return "desktop";
}

/**
 * Generate the HTML certificate download page.
 * @param ua User-Agent string for platform detection
 * @param overrideHost Optional host (ip:port or hostname:port) to use for the download link.
 *                     When a LAN device accesses the proxy directly by IP, this ensures the
 *                     download link points back to the same accessible address.
 * @param certHash Optional OpenSSL subject_hash_old for Android system cert filename.
 */
export function generateCertPage(ua: string, overrideHost?: string, certHash?: string): string {
  const platform = detectPlatform(ua);
  const defaultHost = platform === "ios" ? CERT_DOWNLOAD_HOST : CERT_DOWNLOAD_FALLBACK_HOST;
  const downloadHost = overrideHost || defaultHost;
  const certHref = platform === "android"
    ? `http://${downloadHost}/cert.pem`
    : `http://${downloadHost}/cert.cer`;
  const btnLabel = platform === "android" ? "⬇ 下载证书（PEM 格式）" : "⬇ 下载证书";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anything Analyzer - 安装 CA 证书</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#1e293b;border-radius:16px;padding:32px 28px;max-width:420px;width:100%;box-shadow:0 25px 50px rgba(0,0,0,.4)}
.logo{text-align:center;margin-bottom:24px}
.logo svg{width:48px;height:48px}
h1{font-size:20px;text-align:center;margin-bottom:8px;color:#f8fafc}
.subtitle{text-align:center;font-size:14px;color:#94a3b8;margin-bottom:28px}
.download-btn{display:block;width:100%;padding:14px;border:none;border-radius:12px;font-size:16px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;transition:all .2s;margin-bottom:16px}
.download-btn.primary{background:linear-gradient(135deg,#3b82f6,#6366f1);color:#fff}
.download-btn.primary:active{transform:scale(.98);opacity:.9}
.platform-tag{display:inline-block;background:#334155;color:#94a3b8;padding:3px 10px;border-radius:20px;font-size:12px;margin-bottom:20px}
.steps{background:#0f172a;border-radius:12px;padding:20px;margin-top:4px}
.steps h2{font-size:15px;margin-bottom:14px;color:#f1f5f9}
.step{display:flex;gap:12px;margin-bottom:14px;font-size:13px;line-height:1.6;color:#cbd5e1}
.step:last-child{margin-bottom:0}
.step-num{flex-shrink:0;width:22px;height:22px;border-radius:50%;background:#334155;color:#60a5fa;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;margin-top:1px}
.note{margin-top:20px;padding:14px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:10px;font-size:12px;color:#fbbf24;line-height:1.6}
.note strong{color:#fcd34d}
.tabs{display:flex;gap:8px;margin-bottom:16px}
.tab{flex:1;padding:8px;border:1px solid #334155;border-radius:8px;background:transparent;color:#94a3b8;font-size:13px;cursor:pointer;text-align:center;transition:all .2s}
.tab.active{background:#334155;color:#f1f5f9;border-color:#475569}
.tab-content{display:none}
.tab-content.active{display:block}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#3b82f6" stroke-width="2"/><path d="M24 12v10l7 7" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round"/><circle cx="24" cy="24" r="4" fill="#3b82f6"/></svg>
  </div>
  <h1>安装 CA 证书</h1>
  <p class="subtitle">Anything Analyzer 需要安装根证书以解密 HTTPS 流量</p>
  <div style="text-align:center"><span class="platform-tag" id="platformTag">${platform === "ios" ? "🍎 iOS" : platform === "android" ? "🤖 Android" : "💻 桌面端"}</span></div>

  <a class="download-btn primary" href="${certHref}" id="downloadBtn">${btnLabel}</a>

  <div class="tabs">
    <button class="tab${platform === "ios" ? " active" : ""}" onclick="showTab('ios', this)">iOS</button>
    <button class="tab${platform === "android" ? " active" : ""}" onclick="showTab('android', this)">Android</button>
    <button class="tab${platform === "desktop" ? " active" : ""}" onclick="showTab('desktop', this)">桌面端</button>
  </div>

  <div id="tab-ios" class="tab-content${platform === "ios" ? " active" : ""}">
    <div class="steps">
      <h2>iOS 安装步骤</h2>
      <div class="step"><span class="step-num">1</span><span>确保 iPhone/iPad 与电脑连接在<strong>同一局域网</strong>下</span></div>
      <div class="step"><span class="step-num">2</span><span>打开 iPhone 的「设置」→「Wi-Fi」→ 点击当前连接的 Wi-Fi 名称右侧的 <strong>ⓘ</strong> 按钮</span></div>
      <div class="step"><span class="step-num">3</span><span>滚动到底部，点击「配置代理」→ 选择「手动」→ 填写服务器为<strong>电脑的 IP 地址</strong>，端口为 <strong>代理端口号</strong>（默认 8888）→ 点击「存储」</span></div>
      <div class="step"><span class="step-num">4</span><span>打开 Safari 浏览器（<strong>必须用 Safari</strong>，其他浏览器无法触发描述文件安装），访问本页面并点击上方「下载证书」按钮</span></div>
      <div class="step"><span class="step-num">5</span><span>弹出「此网站正尝试下载一个配置描述文件，要允许吗？」→ 点击「允许」</span></div>
      <div class="step"><span class="step-num">6</span><span>提示「已下载描述文件」后，打开「设置」→「通用」→「VPN 与设备管理」（或「描述文件与设备管理」）</span></div>
      <div class="step"><span class="step-num">7</span><span>找到「Anything Analyzer CA」描述文件，点击进入 → 点击右上角「安装」→ 输入<strong>锁屏密码</strong> → 再次点击「安装」确认</span></div>
      <div class="step"><span class="step-num">8</span><span><strong>⚠ 关键步骤：</strong>前往「设置」→「通用」→「关于本机」→ 滚动到最底部 → 点击「证书信任设置」</span></div>
      <div class="step"><span class="step-num">9</span><span>在「针对根证书启用完全信任」列表中，找到「Anything Analyzer CA」→ <strong>打开右侧开关</strong> → 弹出警告框点击「继续」</span></div>
      <div class="step"><span class="step-num">10</span><span>✅ 安装完成！打开 Safari 访问任意 HTTPS 网站，验证地址栏无证书警告即为成功</span></div>
    </div>
    <div class="note"><strong>⚠ 常见问题：</strong><br>
    • <strong>找不到「VPN 与设备管理」？</strong> → 不同 iOS 版本名称不同，可能叫「描述文件」或「描述文件与设备管理」<br>
    • <strong>安装后仍报证书错误？</strong> → 99% 是因为没有执行第 8-9 步的「证书信任设置」，这是 iOS 的硬性要求<br>
    • <strong>非 Safari 浏览器下载无反应？</strong> → iOS 仅允许 Safari 安装描述文件，请切换到 Safari 重新下载<br>
    • <strong>使用完毕后</strong> → 记得回到 Wi-Fi 设置将代理改回「关闭」或「自动」</div>
  </div>

  <div id="tab-android" class="tab-content${platform === "android" ? " active" : ""}">
    <div class="steps">
      <h2>Android 安装步骤</h2>
      <div class="step"><span class="step-num">1</span><span>确保手机与电脑连接在<strong>同一局域网</strong>下</span></div>
      <div class="step"><span class="step-num">2</span><span>打开「设置」→「WLAN」→ <strong>长按</strong>当前连接的 Wi-Fi（或点击齿轮图标）→ 选择「修改网络」</span></div>
      <div class="step"><span class="step-num">3</span><span>展开「高级选项」→ 代理选择「手动」→ 主机名填<strong>电脑的 IP 地址</strong>，端口填 <strong>代理端口号</strong>（默认 8888）→ 保存</span></div>
      <div class="step"><span class="step-num">4</span><span>打开浏览器，点击上方「下载证书」按钮，系统会自动弹出证书安装界面，按提示完成安装</span></div>
      <div class="step"><span class="step-num">5</span><span>安装后在「设置」→「安全」→「加密与凭据」→「信任的凭据」→「用户」选项卡中确认能看到「Anything Analyzer CA」</span></div>
      <div class="step"><span class="step-num">6</span><span>打开浏览器访问任意 HTTPS 网站验证（<strong>用户 CA 对浏览器有效</strong>）</span></div>
    </div>
    <div class="steps" style="margin-top:12px">
      <h2>🔧 Root 用户：将证书移入系统信任区（让所有 App 信任）</h2>
      <div class="step"><span class="step-num">1</span><span>点击上方「下载证书」按钮下载 PEM 格式证书，或点击下方绿色按钮直接下载已命名好的 <code>${certHash || "xxxxxxxx"}.0</code> 文件</span></div>
      <div class="step"><span class="step-num">2</span><span>如果使用上方按钮下载，需将文件重命名为 <code>${certHash || "xxxxxxxx"}.0</code>（如果使用绿色按钮则无需重命名）</span></div>
      <div class="step"><span class="step-num">3</span><span>将下载的 <code>${certHash || "xxxxxxxx"}.0</code> 文件复制到系统证书目录：<br><code>/system/etc/security/cacerts/</code></span></div>
      <div class="step"><span class="step-num">4</span><span><strong>⚠ 必须重启设备！</strong>Android 在开机时加载系统证书，添加文件后必须重启才能生效</span></div>
      <div class="step"><span class="step-num">5</span><span>重启后在「设置」→「安全」→「信任的凭据」→「系统」选项卡中确认能看到「Anything Analyzer CA」</span></div>
    </div>
    <a class="download-btn primary" href="http://${downloadHost}/cert.android-system" style="background:linear-gradient(135deg,#10b981,#059669);margin-top:4px">⬇ 下载系统证书（Root 用）</a>
    <div class="steps" style="margin-top:12px">
      <h2>🔧 不同 Android 品牌的设置路径</h2>
      <div class="step"><span class="step-num">•</span><span><strong>小米/Redmi (MIUI/HyperOS)：</strong>设置 → 密码与安全 → 系统安全 → 加密与凭据 → 安装证书 → CA 证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>华为/荣耀 (HarmonyOS)：</strong>设置 → 安全 → 更多安全设置 → 加密和凭据 → 从存储设备安装 → CA 证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>OPPO/realme (ColorOS)：</strong>设置 → 密码与安全 → 系统安全 → 安装证书 → CA 证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>vivo (OriginOS/FuntouchOS)：</strong>设置 → 安全与隐私 → 更多安全设置 → 加密与凭据 → 安装证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>三星 (One UI)：</strong>设置 → 生物识别和安全 → 其他安全设置 → 安装证书 → CA 证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>Google Pixel (原生)：</strong>设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书</span></div>
      <div class="step"><span class="step-num">•</span><span><strong>找不到入口？</strong>在设置中搜索「<strong>证书</strong>」或「<strong>凭据</strong>」关键词即可快速定位</span></div>
    </div>
    <div class="note"><strong>⚠ Android 特别说明：</strong><br>
    • <strong>Android 7.0+ 限制：</strong>用户安装的 CA 证书默认只对<strong>浏览器</strong>有效，大部分 App 不信任用户 CA。这是 Google 的安全策略，属于正常现象<br>
    • <strong>如需让所有 App 信任：</strong>需要 Root 权限 + 将证书移入系统证书目录（/system/etc/security/cacerts/），或使用 Magisk + MoveUserCertificates 模块<br>
    • <strong>移入系统目录后必须重启！</strong>Android 在开机时加载系统证书，仅复制文件不会立即生效<br>
    • <strong>系统证书必须是 PEM 格式：</strong>上方「下载证书」按钮在 Android 设备上已自动提供 PEM 格式，可直接用于系统证书安装（需重命名为 <code>{hash}.0</code>），或使用绿色按钮获取已命名好的文件<br>
    • <strong>安装时要求设置锁屏？</strong>这是 Android 安全要求，安装 CA 证书必须设置 PIN/密码/图案锁屏<br>
    • <strong>使用完毕后</strong> → 记得回到 Wi-Fi 设置将代理改回「无」</div>
  </div>

  <div id="tab-desktop" class="tab-content${platform === "desktop" ? " active" : ""}">
    <div class="steps">
      <h2>桌面端安装步骤</h2>
      <div class="step"><span class="step-num">1</span><span>推荐直接在 Anything Analyzer 应用内点击「安装证书」按钮一键安装</span></div>
      <div class="step"><span class="step-num">2</span><span>或下载证书后手动双击安装到系统信任存储中（Windows 选择「受信任的根证书颁发机构」）</span></div>
      <div class="step"><span class="step-num">3</span><span>macOS 用户需在「钥匙串访问」中找到证书 → 双击 → 展开「信任」→ 设为「始终信任」</span></div>
    </div>
  </div>
</div>
<script>
function showTab(name, el){
  document.querySelectorAll('.tab-content').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if (el) el.classList.add('active');
}
</script>
</body>
</html>`;
}

/**
 * Get the CA certificate content as PEM-encoded Buffer for download.
 */
export function getCertFileContent(caManager: CaManager): Buffer {
  const certPath = caManager.getCaCertPath();
  const raw = readFileSync(certPath, "utf-8");
  // Ensure LF line endings for Android system cert compatibility
  return Buffer.from(raw.replace(/\r\n/g, "\n"), "utf-8");
}

/**
 * Get the CA certificate content as DER-encoded Buffer for mobile download (.cer).
 */
export function getCertDerContent(caManager: CaManager): Buffer {
  return caManager.getCaCertDer();
}
