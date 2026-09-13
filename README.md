# Tun2Proxy for KernelSU

一个模块提供 root TUN 代理、App UID 分流与 Android CA 管理。
不依赖独立代理 App 或 MoveCertificate 模块。证书与代理生命周期相互独立。

## 连接与代理范围

在 KernelSU 打开 WebUI，或访问手机的 `http://127.0.0.1:38765`。
连接配置仍是唯一上游设置：HTTP CONNECT（Yakit/Burp）、SOCKS5 或 SOCKS5h。
电脑局域网地址、监听端口及可选用户名/密码统一保存在已有 `proxy_url`。
证书页面只读该配置；修改连接后请保存，再重新测试 Yakit。

代理范围保持“仅运行引擎 / 选定主用户 App / 全部非 root 本机流量”。
DNS、TUN、TCP/UDP 超时、UDP Gateway、Bypass、Auto Start 均沿用现有配置。
详细范围与协议限制见 [ROUTING.md](ROUTING.md)。

## Yakit 证书管理

1. 在连接配置保存电脑上的 Yakit HTTP CONNECT 地址与认证。
2. 打开“证书管理”→“测试 Yakit”。
3. 确认识别为 Yakit 后，点击“同步 Yakit 证书”。
4. 普通 CA →“加入系统”。安装前请核对指纹。
5. “移出系统”只撤销本模块注入，保留缓存及用户原证书。

探测由 root Go 后端通过显式 HTTP Proxy 访问 `http://mitm/`，不是
WebView 直接 fetch，不解析 mitm DNS，不改全局或 Wi-Fi Proxy。
HTTP CONNECT 不等于 Yakit：Burp/其他代理页面显示“可连接但未识别”。
普通与国密分别记录本地/远程 SHA-256、真实下载端点、下载及更新时间。
检查更新不替换本地缓存；同步先下载验证，新挂载校验通过后才提交 inventory。

实测首页是 HTML，下载按钮的 href 分别为：
- 普通：`http://mitm/download-mitm-crt`
- 国密：`http://mitm/download-mitm-gm-crt`

先验证已知端点，失败再尝试页面链接或字面量 JavaScript URL。
不会执行页面 JavaScript；跨域跳转、私钥端点、HTML 和非 CA 内容均被拒绝。
只处理一张公共 X.509 证书，不接收私钥、PKCS12 或 PEM bundle。

## 本机证书

- 用户证书：列出 Android 用户目录中的 CA。加入系统先复制到私有托管缓存，
  原用户 CA 保留。“删除用户证书”是独立确认操作，先写私有恢复副本再删除。
- 模块托管/缓存：可导入 .crt/.cer/.pem/.der，查看、导出、加入或移出系统。
  已安装证书不能直接删除缓存，须先移出系统。
- 系统证书：只读，不提供删除或移出操作。若另有模块，显示当前可见系统库，
  其中可能包含该模块的证书，本模块不会将其当作可删除对象。

文件导入使用 KernelSU 已支持的 HTML file chooser 接口，不接受手填手机路径。
需要支持文件选择的 KernelSU Manager；旧版可从本机浏览器打开同一个控制台。
后端使用 256 KiB 上限，私有目录0700、缓存0600，稳定 SHA-256 ID，
不使用 UI 下标或前端路径执行文件操作。

证书管理 API 仅允许 loopback 请求、匹配 Host/Origin 及专用操作头。
桌面可通过 `adb forward tcp:38765 tcp:38765` 打开同一页面。
原来的局域网代理控制页不因此获得远程证书管理权限。

## Android systemless 实现

兼容层分为 detect / plan / apply / verify / remove：
- Android 7–13：目标为 /system/etc/security/cacerts。
- Android 14–16：从活动 /apex/com.android.conscrypt 解析实际版本别名，
  并覆盖活动和版本化 cacerts 路径；检查 init、zygote/zygote64 命名空间。
- 使用包含原始证书与托管 CA 的私有 generation 进行 bind mount，
  不 remount /system rw，不写底层 system/APEX 分区。
- 文件名使用 subject_hash_old（subject DER 的 MD5，little endian），
  内容 ID 使用 SHA-256。冲突使用 .0/.1/.2，不覆盖不同证书。
- 应用时保留上一代；挂载与指纹验证失败撤回新层。正常证书必须在该 ROM 的
  AndroidCAStore system alias 中找到，才报告可用。
- 挂载源归属检查拒绝叠加其他证书模块的活动挂载。
  迁移时需用户确认停用原模块并重启；不会自动卸载或删除它的证书。
- 开机独立恢复已托管证书，不自动联网同步，不影响 tun2proxy 启动。
  晚启动时已运行 App 可能保留旧命名空间/TrustManager，请重开 App；
  个别 ROM 需要重启。移除后同样适用。
- 卸载撤销本模块挂载；失败则保留私有数据以便恢复，重启后恢复底层系统库。
  绝不删除用户 CA 或 stock CA。

Android 7–13、14、16 的设备矩阵仍需要对应实机验证，不能把 Android 15
上的结果当作所有 ROM 的保证。当前发布验证范围见下方报告。

Android 15 已实测普通 CA 加入/移出、用户 CA 复制保留原件及重启恢复。
Android 默认 TrustManager 经 Yakit 的 HTTPS 对照：
加入后HTTP200，移出后SSLHandshakeException，再次加入恢复HTTP200。
MoveCertificate可保留安装，但不要同时启用两个覆盖同一CA库的注入模块。

## 国密限制

Go 解析器能读取 SM2 CA 元数据，但不将 ASN.1 解码视作签名或系统信任验证。
Android 原生 CertificateFactory、公钥/自签名校验与 AndroidCAStore 分别检测。
只有原生签名能力可用时，才开放验证式安装；安装后仍须系统库校验通过。

本测试机 Android 15 的 AndroidOpenSSL 可解析 Yakit GM CA，
但不能完成其签名验证，因此禁止系统安装。下载、同步、检查更新、
查看、导出、删除缓存均不受影响。不会虚报“系统已信任”。

## HTTPS 限制

系统信任 CA 不等于所有 App HTTPS 可解密。Certificate Pinning、自带 trust store、
native TLS、国密 TLS 等可能继续拒绝代理。模块不承诺绕过这些机制。
根 TUN 不注册 Android VpnService，但 TUN 本身仍可被检查。

## 构建与测试

Go 后端不引入额外通用运行时，证书辅助使用系统 ART 运行约2 KiB DEX。
不依赖手机的 curl、wget、openssl。

Windows（Go 1.26.4、JDK、Android SDK Build Tools 36.0.0）：

```powershell
# 原代理引擎首次构建，后续证书修改无需重建Rust
./build-tun2proxy.ps1 -Ref v0.8.3
./cmd/build-certificates.ps1
cd cmd/tun2proxy-web
go test ./certificate ./yakit
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go vet ./...
go build -ldflags='-s -w' -o ../../system/bin/tun2proxy-web .
go test -c -o ../cert-tests .
cd ../..
./pack.ps1
```

Go 主包含 Linux flock，主包测试交叉编译后在 Android 执行；
certificate/yakit 纯逻辑包可在开发机直接测试。
代码与测试在 cmd/，不进入 ZIP；运行时为原引擎、Go服务、证书DEX及同一个 WebUI。
每次新 release ZIP 的 patch 版本递增，禁止覆盖同版本包。

[实现与验收记录](docs/CERTIFICATE-IMPLEMENTATION.md)。

Certificate compatibility layer inspired by MoveCertificate.
参考 [ys1231/MoveCertificate](https://github.com/ys1231/MoveCertificate)；
归属与许可证见 NOTICE 和 LICENSES/MoveCertificate-Apache-2.0.txt。
