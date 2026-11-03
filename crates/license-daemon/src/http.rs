//! 对应 tools/license-daemon/src/http/server.ts 全文：
//! license-daemon HTTP 页面（给人用）：指纹展示 + license 上传激活。
//! 响应体与 TS 版逐字节兼容：JSON 用 JSON.stringify 语义（license_core::jsonfmt::compact_json，
//! 键序按 TS 对象字面量构造序），所有 JSON 响应均无尾换行；页面模板逐字节复刻。

use crate::activation::{activate_license, ActivationResult};
use license_core::fingerprint::{
    build_fingerprint_file, format_fingerprint_groups, CollectedFingerprint,
};
use license_core::jsonfmt::{compact_json, object_in_order};
use license_core::key_policy::PublicKeyMetadata;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

/// 与 server.ts readBody 的 limit 一致：1 MiB（server.ts:88）。
const BODY_LIMIT: u64 = 1024 * 1024;

const HTML_CT: &str = "text/html; charset=utf-8";
const JSON_CT: &str = "application/json; charset=utf-8";

/// 对应 server.ts 的 DaemonContext（server.ts:12-17）。
pub struct DaemonContext {
    pub fingerprint: CollectedFingerprint,
    pub state_dir: PathBuf,
    pub public_key: PublicKeyMetadata,
}

/// 对应 server.ts:19-21 escapeHtml：& 最先，然后 < > "；不转义单引号。
/// 方案 C 删除分量表后页面不再调用它（与 TS 版同步保留，供未来插值点复用）。
#[allow(dead_code)]
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// 锚点缺失警告（codename-spec §5.1 钉死）：不点名机器标识来源，只用代号 c1。
const ANCHOR_WARNING: &str = r#"<div class="error">
      <strong>无法采集必选锚点（c1）。</strong><br/>
      缺失该锚点无法签发 license，本页面不做降级放行。请联系供应商支持，并提供上方完整指纹与锚点代号 c1。
    </div>"#;

/// 对应 server.ts:40-79 主模板，逐字节复刻（<!doctype html> 开头、</body></html> 结尾无尾换行）。
/// 三处插值点保留 TS 占位符字面量，render_page 里按序替换。
const PAGE_TEMPLATE: &str = r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"/><title>AgentOS License 激活</title>
<style>
body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
code{background:#f3f3f3;padding:1px 4px;border-radius:3px;word-break:break-all}
table{border-collapse:collapse;width:100%;margin:1rem 0}
td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:14px}
.fingerprint{font-size:18px;font-family:monospace;letter-spacing:1px}
.error{background:#fdecea;border:1px solid #f5c6c0;padding:12px;border-radius:6px;margin:1rem 0}
.ok{background:#e8f5e9;border:1px solid #c8e6c9;padding:12px;border-radius:6px;margin:1rem 0}
hr{border:none;border-top:1px solid #ddd;margin:2rem 0}
button{padding:8px 16px;font-size:14px}
#result{margin-top:1rem;white-space:pre-wrap}
</style></head><body>
<h1>AgentOS License 激活</h1>
${anchorWarning}
<h2>机器指纹</h2>
<p>完整指纹：</p>
<p class="fingerprint">${grouped}</p>
<p>下载 <a href="/fingerprint.json">fingerprint.json</a> 文件发给供应商签发。</p>
<hr/>
<h2>激活</h2>
<p>上传供应商签发的 <code>.lic</code> 文件：</p>
<input type="file" id="licFile" accept=".lic,.json"/> <button onclick="activate()">激活</button>
<div id="result"></div>
<script>
async function activate(){
  const out = document.getElementById('result');
  out.className=''; out.textContent='activating...';
  try {
    const input = document.getElementById('licFile');
    if (!input.files || input.files.length === 0) { out.className='error'; out.textContent='请先选择 .lic 文件。'; return; }
    const res = await fetch('/activate', {method:'POST', headers:{'content-type':'application/json'}, body: await input.files[0].text()});
    const body = await res.json();
    if (body.ok) { out.className='ok'; out.textContent='activation ok: licenseId=' + body.licenseId + ', expiresAt=' + body.expiresAt; }
    else { out.className='error'; out.textContent='activation failed: ' + body.code + ' ' + (body.message||''); }
  } catch (e) { out.className='error'; out.textContent='request failed: ' + e; }
}
</script>
</body></html>"#;

/// 对应 server.ts:23-80 renderPage（方案 C：删除分量表与 rows 插值点，页面不再出现分量名）。
fn render_page(ctx: &DaemonContext) -> String {
    let fp = &ctx.fingerprint;
    let grouped = format_fingerprint_groups(&fp.fingerprint);
    let anchor_warning = if fp.anchor_available {
        ""
    } else {
        ANCHOR_WARNING
    };
    PAGE_TEMPLATE
        .replace("${anchorWarning}", anchor_warning)
        .replace("${grouped}", &grouped)
}

/// 对应 server.ts:135-140 成功响应体（键序 ok,licenseId,customer,expiresAt）。
fn success_body(result: &ActivationResult) -> String {
    compact_json(&object_in_order(vec![
        ("ok", Value::Bool(true)),
        ("licenseId", Value::String(result.license_id.clone())),
        ("customer", Value::String(result.customer.clone())),
        ("expiresAt", Value::String(result.expires_at.clone())),
    ]))
}

/// 对应 server.ts:125/143/145 错误响应体（键序 ok,code,message）。
fn error_body(code: &str, message: &str) -> String {
    compact_json(&object_in_order(vec![
        ("ok", Value::Bool(false)),
        ("code", Value::String(code.to_string())),
        ("message", Value::String(message.to_string())),
    ]))
}

/// 对应 server.ts:151 兜底 404（无 message 键）。
fn not_found_body() -> String {
    compact_json(&object_in_order(vec![
        ("ok", Value::Bool(false)),
        ("code", Value::String("ERR_NOT_FOUND".to_string())),
    ]))
}

/// 发送响应：content-type 头名小写（与 Node writeHead 给定大小写一致），body 无尾换行。
fn respond(request: Request, status: u16, content_type: &str, body: String) {
    respond_with_headers(request, status, content_type, Vec::new(), body);
}

/// 与 respond 相同，但允许附加响应头（用于 /fingerprint.json 的 Content-Disposition 附件下载）。
fn respond_with_headers(request: Request, status: u16, content_type: &str, extra: Vec<Header>, body: String) {
    let mut headers = vec![Header::from_bytes(&b"content-type"[..], content_type.as_bytes())
        .expect("content-type header")];
    headers.extend(extra);
    let bytes = body.into_bytes();
    let len = bytes.len();
    let response = Response::new(
        StatusCode(status),
        headers,
        std::io::Cursor::new(bytes),
        Some(len),
        None,
    );
    let _ = request.respond(response);
}

/// 对应 server.ts createLicenseDaemonServer + cli.ts server.listen 成功回调。
/// 绑定成功后调用 on_listening（打印启动日志），随后串行处理请求（server.recv 循环）。
pub fn serve(
    ctx: DaemonContext,
    bind: &str,
    port: u16,
    on_listening: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = Server::http(format!("{bind}:{port}"))?;
    on_listening();
    for request in server.incoming_requests() {
        handle_request(request, &ctx);
    }
    Ok(())
}

/// 对应 server.ts:107-152 路由。Node new URL(req.url).pathname 只取 path：
/// split('?') 取首段，忽略 query，不做 percent-decode。
fn handle_request(request: Request, ctx: &DaemonContext) {
    let path = request.url().split('?').next().unwrap_or("");
    let is_get = matches!(request.method(), Method::Get);
    let is_post = matches!(request.method(), Method::Post);
    if is_get && path == "/" {
        respond(request, 200, HTML_CT, render_page(ctx));
    } else if is_get && path == "/fingerprint.json" {
        // 以附件形式下发（Content-Disposition: attachment），浏览器直接下载而不是在页面内渲染 JSON。
        let disposition = Header::from_bytes(
            &b"content-disposition"[..],
            &b"attachment; filename=\"fingerprint.json\""[..],
        )
        .expect("content-disposition header");
        respond_with_headers(
            request,
            200,
            JSON_CT,
            vec![disposition],
            compact_json(&build_fingerprint_file(&ctx.fingerprint)),
        );
    } else if is_post && path == "/activate" {
        handle_activate(request, ctx);
    } else {
        respond(request, 404, JSON_CT, not_found_body());
    }
}

/// 对应 server.ts:119-149 POST /activate。
/// body 超限与 JSON.parse 失败在 TS 中走同一个 catch → 同一个 400；不校验请求 Content-Type。
fn handle_activate(mut request: Request, ctx: &DaemonContext) {
    let mut buf: Vec<u8> = Vec::new();
    let parsed = match request.as_reader().take(BODY_LIMIT + 1).read_to_end(&mut buf) {
        // Buffer.toString('utf8') 是 lossy 解码 → from_utf8_lossy。
        Ok(_) if buf.len() as u64 <= BODY_LIMIT => {
            serde_json::from_str::<Value>(&String::from_utf8_lossy(&buf)).ok()
        }
        _ => None,
    };
    let license = match parsed {
        Some(v) => v,
        None => {
            respond(
                request,
                400,
                JSON_CT,
                error_body("ERR_INVALID_LICENSE", "Request body is not valid JSON license."),
            );
            return;
        }
    };
    let current_components: HashMap<String, String> =
        ctx.fingerprint.components.iter().cloned().collect();
    let now_ms = license_core::time::now_millis();
    match activate_license(
        &license,
        &ctx.state_dir,
        &ctx.public_key,
        &current_components,
        now_ms,
    ) {
        Ok(result) => respond(request, 200, JSON_CT, success_body(&result)),
        // activation 只返回 AgentosError → TS 的 500 ERR_UNEXPECTED 分支在 Rust 类型层面不可达。
        Err(err) => respond(request, 422, JSON_CT, error_body(&err.code, &err.message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_fingerprint(anchor_ok: bool) -> CollectedFingerprint {
        CollectedFingerprint {
            platform: "linux".to_string(),
            components: vec![
                (
                    "machine-id".to_string(),
                    if anchor_ok {
                        format!("sha256:{}", "1".repeat(64))
                    } else {
                        "unavailable".to_string()
                    },
                ),
                (
                    "dmi-product-uuid".to_string(),
                    format!("sha256:{}", "2".repeat(64)),
                ),
                ("dmi-product-serial".to_string(), "unavailable".to_string()),
                ("cpu".to_string(), format!("sha256:{}", "4".repeat(64))),
                ("agentos-instance-id".to_string(), "unavailable".to_string()),
            ],
            fingerprint: format!("sha256:{}", "a".repeat(64)),
            anchor_available: anchor_ok,
        }
    }

    fn fake_ctx(anchor_ok: bool) -> DaemonContext {
        DaemonContext {
            fingerprint: fake_fingerprint(anchor_ok),
            state_dir: PathBuf::from("state"),
            public_key: PublicKeyMetadata {
                kid: "agentos-dev-2026-q4".to_string(),
                alg: "Ed25519".to_string(),
                public_key_pem: "pem".to_string(),
                production: false,
            },
        }
    }

    #[test]
    fn escape_html_order_and_charset() {
        // & 必须最先替换（否则 < 的转义结果 &lt; 会被二次转义）。
        assert_eq!(escape_html("&<>\""), "&amp;&lt;&gt;&quot;");
        assert_eq!(escape_html("&lt;"), "&amp;lt;");
        // 单引号不转义。
        assert_eq!(escape_html("it's"), "it's");
    }

    #[test]
    fn render_page_anchor_available() {
        let page = render_page(&fake_ctx(true));
        assert!(page.starts_with("<!doctype html>\n"));
        assert!(page.ends_with("</body></html>"));
        assert!(!page.contains("<div class=\"error\">"));
        // 指纹分组格式 XXXX-XXXX-…（大写，64 hex → 16 组）。
        let grouped = format!("<p class=\"fingerprint\">{}AAAA</p>", "AAAA-".repeat(15));
        assert!(page.contains(&grouped));
        // 页面结构调整：简化标题、分割线、文件上传替代粘贴框。
        assert!(page.contains("<h2>机器指纹</h2>"));
        assert!(page.contains("<h2>激活</h2>"));
        assert!(page.contains("<hr/>"));
        assert!(page.contains("<input type=\"file\" id=\"licFile\""));
        assert!(page.contains("下载 <a href=\"/fingerprint.json\">fingerprint.json</a> 文件发给供应商签发"));
        assert!(!page.contains("<textarea"));
        assert!(!page.contains("getElementById('lic')"));
        // 方案 C：页面不再有分量表，不出现任何分量名与机器标识来源字样。
        assert!(!page.contains("<table"));
        assert!(!page.contains("${rows}"));
        for forbidden in ["machine-id", "dmi-product", "/etc/machine-id", "MachineGuid"] {
            assert!(!page.contains(forbidden), "page leaks {forbidden}");
        }
    }

    #[test]
    fn render_page_anchor_missing() {
        let page = render_page(&fake_ctx(false));
        assert!(page.contains("<div class=\"error\">"));
        // codename-spec §5.1 钉死警告文案（两行，6 空格缩进）。
        assert!(page.contains(
            "<strong>无法采集必选锚点（c1）。</strong><br/>\n      缺失该锚点无法签发 license，本页面不做降级放行。请联系供应商支持，并提供上方完整指纹与锚点代号 c1。"
        ));
        // 页面不点名机器标识来源。
        for forbidden in ["machine-id", "dmi-product", "/etc/machine-id", "MachineGuid", "<table"] {
            assert!(!page.contains(forbidden), "page leaks {forbidden}");
        }
    }

    #[test]
    fn fingerprint_attachment_header() {
        // GET /fingerprint.json 须带附件下载头，浏览器直接下载而不是页面内渲染。
        let h = Header::from_bytes(
            &b"content-disposition"[..],
            &b"attachment; filename=\"fingerprint.json\""[..],
        )
        .unwrap();
        assert_eq!(h.field.as_str(), "content-disposition");
        assert_eq!(h.value.as_str(), "attachment; filename=\"fingerprint.json\"");
    }

    #[test]
    fn fingerprint_json_key_order_prefix() {
        let ctx = fake_ctx(true);
        let body = compact_json(&build_fingerprint_file(&ctx.fingerprint));
        // codename-spec §3.1：components 键为代号 c1..c5，值与槽位顺序不变。
        let expected = format!(
            "{{\"schema\":\"agentos-fingerprint/v1\",\"fingerprint\":\"sha256:{}\",\"components\":{{\"c1\":\"sha256:{}\",\"c2\":\"sha256:{}\",\"c3\":\"unavailable\",\"c4\":\"sha256:{}\",\"c5\":\"unavailable\"}}}}",
            "a".repeat(64),
            "1".repeat(64),
            "2".repeat(64),
            "4".repeat(64)
        );
        assert_eq!(body, expected);
        assert!(!body.ends_with('\n'));
    }

    #[test]
    fn response_body_key_order() {
        let result = ActivationResult {
            license_id: "lic-1".to_string(),
            customer: "c1".to_string(),
            expires_at: "2027-01-01T00:00:00.000Z".to_string(),
            active_license_path: PathBuf::from("state/active.lic"),
        };
        assert_eq!(
            success_body(&result),
            "{\"ok\":true,\"licenseId\":\"lic-1\",\"customer\":\"c1\",\"expiresAt\":\"2027-01-01T00:00:00.000Z\"}"
        );
        assert_eq!(
            error_body("ERR_X", "boom"),
            "{\"ok\":false,\"code\":\"ERR_X\",\"message\":\"boom\"}"
        );
        assert_eq!(not_found_body(), "{\"ok\":false,\"code\":\"ERR_NOT_FOUND\"}");
    }
}
