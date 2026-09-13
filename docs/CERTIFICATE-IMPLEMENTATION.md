# 证书集成实现与验收记录

状态：**Android 15 / SDK35 独立系统CA与代理回归验证通过**；其他Android版本尚无对应实机。
日期：2026-09-13。发布版本 v1.0.22 / versionCode 23。

## 1. Git commit

最终提交号由交付消息与 `git log -1` 给出；本文不嵌入自己的提交哈希。

## 2–3. 修改文件与新增组件

- `cmd/tun2proxy-web/certificate/{certificate,store}.go`：公共CA解析、SHA256、subject_hash_old、私有inventory。
- `cmd/tun2proxy-web/yakit/client.go`：显式代理、认证复用、识别与端点发现。
- `cmd/tun2proxy-web/cert_api.go`：原HTTP服务新增证书API、用户/系统枚举、事务操作、审计。
- `cmd/tun2proxy-web/cert_mount.go`：Android detect/plan/apply/verify/remove。
- `cmd/certificate-probe/CertificateProbe.java`：系统原生解析、签名、AndroidCAStore校验。
- `cmd/build-certificates.ps1` / `system/framework/certificate-probe.jar`：约2KiB DEX构建与产物。
- `certificate/service.sh`、service.sh、uninstall.sh：独立恢复与本模块挂载清理。
- main.go、webroot/index.html、webroot/certificates.js：现有服务、导航、日志、诊断接入。
- certificate/yakit及主包测试、README.md、NOTICE、LICENSES、版本与打包脚本。
- Go模块清单开始纳入Git；原UID分流及TUN代码作为当前仓库基线保留。

## 4–5. 配置复用

只读取现有 `Config.ProxyURL`，JSON字段 `proxy_url`。
通过 net/url 解析 scheme/host/port/User，HTTP Transport复用其中用户名/密码。
未增加任何第二套Yakit连接配置，也未改变Proxy URL的前端生成逻辑。
新增的是独立 `certificates/inventory.json` 与 `mounts.json`，不是连接配置字段。
原 route_mode/app_packages/enabled/tun_name/dns_mode/bypass_ips/timeouts/udpgw_server 保持语义。

## 6–9. 实际Yakit网页与发现

通过测试机root后端→已保存 `http://192.168.30.102:8083`→`http://mitm/`，
返回HTTP200 HTML，标题MITM，带 `/static/yakit-logo.png`、两个certificate-down链接，
以及yaklang官方教程链接。不是直接返回CA。

普通真实endpoint：`http://mitm/download-mitm-crt`。
国密真实endpoint：`http://mitm/download-mitm-gm-crt`。
发现方式：实际页面两个按钮的href，之后由手机后端下载并解析确认。

兼容层：识别Yakit页面→已验证的已知endpoint→严格证书解析→失败时页面href/
字面量JS URL回退→明确错误。不会执行任意远端JS，不跟随跨域/私钥下载。
HTTP407与HTTP404保留清晰状态；普通非Yakit网页不会被当网络连接失败。

## 10–12. 证书操作

普通CA：下载验证→不可变内容寻址缓存→inventory→显式加入系统。
移出只取消managed并重建/撤回本模块视图，缓存保留。
更新先获取新CA，生成并验证新挂载，再切换指纹与managed标记；
旧公共缓存保留以便恢复，不提前删除。

国密CA：独立source yakit-gm与指纹slot，可下载、解析元数据、同步、检查更新、
导出、删除。Android原生探针不能验证SM2签名时禁用安装。
若原生签名能力可用，允许验证式安装，仍要求AndroidCAStore确认，失败回滚。

用户CA：扫描 /data/misc/user/*/cacerts-added，按ID及用户选择。
加入系统先复制，不删除原CA。删除用户CA须明确确认，先备份到私有user-trash。
测试前用户CA目录为空。创建本次测试副本后，枚举/加入/移出均通过，
且用户原件的SHA256保持一致。测试后只清理该副本，并验证私有恢复备份存在。
未删除任何无关证书；当前用户目录恢复为空。

## 13–14. Android兼容

7–13目标/system/etc/security/cacerts；14–16从活动APEX目录解析真实版本别名。
生成保留原始证书的完整目录并bind mount，遵循实际SELinux标签。
init/zygote命名空间分别确认指纹，原生AndroidCAStore检查system alias。
只撤销属于本模块私有runtime源的挂载，拒绝覆盖其他模块。
32层保护提示重启，避免无限叠加；挂载失败回滚，新库存不提交。

7–13/14/16无对应测试机，仅代码路径完成，不宣称实测通过。
Android15在用户授权停用MoveCertificate并重启后，真实安装、移出、再次加入
与重启恢复均通过。原生AndroidCAStore状态与实际HTTPS握手均作了正反对照。

## 15–16. MoveCertificate来源与License

参考最新版固定commit：
[5775fbd43c2dedfcc66e375d6692e0846f3ea334](https://github.com/ys1231/MoveCertificate/tree/5775fbd43c2dedfcc66e375d6692e0846f3ea334)。
阅读post-fs-data.sh、service.sh、common/built-in/compatible/refresh、
用户复制与权限、APEX别名、命名空间及系统基线逻辑。
采用兼容挂载设计思路，但新写Go事务管理器，不执行或内嵌另一套模块。
不沿用其用户目录chmod、按名称删除证书或用户证书移动做法。
Apache-2.0全文在LICENSES，NOTICE与README保留attribution。

文件选择接口依据
[KernelSU官方file chooser变更](https://github.com/tiann/KernelSU/pull/3139)
与[WebUI文档](https://kernelsu.org/guide/module-webui.html)，使用input type=file。

## 17–19. 安全

stock只读；API不接收任意文件路径，只接收64位十六进制ID，用户目录路径由后端扫描。
content size限制256KiB；明确拒绝私钥、非CA、HTML、多个PEM证书。
subject_hash_old同名不同指纹用下个.N，同指纹不重复；SHA256才是安全ID。
证书接口loopback限定、Host/Origin及专用头校验，拒绝DNS rebinding和跨源调用。
代理URL不出现在新证书日志；原启动日志移除命令行认证，配置权限改0600。
helper为UID0，现有路由已排除root；实测Yakit地址路由wlan0，不产生TUN回环。
未修改Android Global Proxy或Wi-Fi Proxy。

## 20. 自动化结果

已通过：
- PEM/DER、invalid/HTML/private key、normal X509、SM2元数据测试。
- 重复SHA256、同subject hash .0/.1、缓存删除与managed删除保护。
- Yakit普通+国密/缺普通/缺国密/HTML变化/字面量JS/错误页面/Burp/private/external fixtures。
- HTTP absolute proxy request、已有认证复用、HTTP404/407、恶意proxy/endpoint。
- Android运行主包测试：loopback/same-origin/LAN/cross-origin/DNS rebinding/缺操作头。
- 真正调用action验证非法ID拒绝。
- 原有全部Config字段往返一致（含UID、DNS、Bypass、AutoStart、认证），0600权限。
- 安装/移出失败不提交inventory，成功提交且移出保留缓存。
- Yakit指纹轮换：check不替换，sync失败保留旧CA，sync成功切换。
- Go arm64交叉编译、go vet、原页inline JavaScript与新JS语法检查。
- 重启路由日志兼容回归：旧boot日志不执行过期规则删除；识别本ROM的
  Couldn't find target T2P_CAPTURE错误，且不忽略权限/锁/其他chain错误。

原仓库没有现成自动化测试套件；以上新增配置回归测试不等于所有代理组合实测。
浏览器交互工具运行时崩溃，尚无视觉/点击自动化通过记录。

## 21. 实机结果

Android 15 / SDK35；ksud4.1.3。
APEX：/apex/com.android.conscrypt 与 /apex/com.android.conscrypt@352090000。
System fallback：/system/etc/security/cacerts。
初期测试保持原PID11822；随后安装v1.0.21并在路由回归中修复旧boot清理，
修复已纳入v1.0.22。临时测试端口38766/38767/38768均已关闭。
全部模式UID2000→tun0并HTTP200；选定模式UID10118→tun0并HTTP200，
未选UID2000→wlan0，root上游→wlan0。真实系统浏览器启动验证通过。

实际Normal SHA256：
7f0b6b7415dbd663ffb5028e385ffab6e89456f95c02a7c9ffb51708532b13b1
实际GM SHA256：
0ac803b920856f2f4c6a09c5283cfeffea361d77cb9c5a9ac66fd3c0fc0ab58c

Normal与GM下载/解析/重复同步/检查更新通过。
GM AndroidOpenSSL：parsed=true，signatureValid=false，trusted=false，安装被拒绝。
起初Normal安装被MoveCertificate活动挂载安全拦截；用户明确授权停用并重启后：
- Normal加入：AndroidCAStore trusted=true；移出：trusted=false，无残余本模块挂载。
- 用户CA复制加入/移出：源文件指纹完全一致；仅清理本次自建测试副本。
- 独立重启恢复：pending=0，普通CA重新可见且trusted=true。
- 卸载所用--cert-remove清理入口通过；未实际卸载整个代理模块。
- 清理后的原厂CA内容汇总SHA256与挂载前基线一致：
  d1a6996a5f4bbac0760495fa7ed5ebc20b933c27d91fbccabd6c00cf7de3c287。
- MoveCertificate的145个证书文件原封不动，前后汇总SHA256均为：
  1c3332f0f28159ad6cfefce9beb8efe01c3d2c1298e8cddac73ac04f632b1641。
- Android默认TrustManager通过Yakit请求HTTPS：安装CA后HTTP200，
  peer为Yakit签发的example.com；移出CA后SSLHandshakeException；
  重新加入后再次HTTP200，没有关闭验证或自定义trust-all。

最终意图：缓存2、managed1、mounted1；普通CA加入，GM仅缓存；用户CA0。
MoveCertificate保留安装文件与所有证书，暂时停用，避免两个模块抢占同一信任库。

## 22. release ZIP

目标：tun2proxy-for-KernelSU-v1.0.22.zip。
仅包含原模块运行时、同一个WebUI与新增小型CA探针；不包含cmd源码或另一套模块。
v1.0.21构建与实际安装成功；v1.0.22纳入重启路由兼容修复与本次验收记录。
最终ZIP校验和、安装状态与Git提交由交付消息给出。

## 23. 已知限制及下一步

- MoveCertificate可以保留安装，但不要与本模块同时启用重叠的CA注入。
- 正常CA与用户CA流程已实测；不同Android版本矩阵、整模块实际卸载、
  浏览器视觉/点击自动化仍未全覆盖，不能给所有设备的验收标准打勾。
- 运行中App可能保留旧CA缓存/命名空间；必须重开，某些ROM需重启。
- 国密不能签名验证，不代表公共CA文件下载失败；不伪报信任。
- 不承诺绕过certificate pinning/native TLS/自带trust store。
- 动态JS计算/外部JS中的新endpoint不执行，未来需针对新页面扩展discovery。
- 不同ROM trust store及SELinux兼容仍需扩展实机矩阵。
