//! Template contracts shared by the control plane and the data plane.
use crate::js_challenge::page::{
    challenge_scripts, ChallengePageParams, REQUIRED_DOM_IDS,
};
use anyhow::{ensure, Result};
use tera::{Context, Tera};

pub const MAX_PAGE_BYTES: usize = 256 * 1024;

pub const PW_STYLE: &str = r##"<style>
:root{
  --bg:#f6f7f9;--card:#ffffff;--fg:#141417;--muted:#6b6b73;--border:#e7e7ea;
  --accent:#f6821f;--code-bg:#fafafb;--shadow:0 24px 60px rgba(20,20,25,.10);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d0d10;--card:#16161a;--fg:#f3f3f5;--muted:#9a9aa4;--border:#26262d;
    --accent:#ff9440;--code-bg:#101014;--shadow:0 24px 60px rgba(0,0,0,.5);
  }
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:24px;color:var(--fg);background-color:var(--bg);
  background-image:
    radial-gradient(60rem 40rem at 12% 15%,rgba(246,130,31,.10),transparent 60%),
    radial-gradient(50rem 40rem at 88% 85%,rgba(246,130,31,.08),transparent 60%);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;
}
.card{
  width:100%;max-width:560px;background:var(--card);border:1px solid var(--border);
  border-radius:18px;padding:44px 36px;box-shadow:var(--shadow);text-align:center;
  animation:rise .5s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.icon{
  width:68px;height:68px;margin:0 auto 18px;border-radius:18px;display:flex;
  align-items:center;justify-content:center;background:rgba(246,130,31,.12);
}
.icon svg{width:36px;height:36px;stroke:var(--accent);fill:none;stroke-width:1.7;
  stroke-linecap:round;stroke-linejoin:round}
.code{
  font-size:15px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;
  color:var(--accent);margin-bottom:6px;
}
h1{font-size:24px;margin:0 0 10px;letter-spacing:-.015em;font-weight:650}
.msg{color:var(--muted);margin:0 0 26px;line-height:1.65;font-size:14.5px}
.details{
  background:var(--code-bg);border:1px solid var(--border);border-radius:12px;
  padding:14px 16px;text-align:left;font-size:13px;
}
.row{display:flex;justify-content:space-between;gap:16px;padding:6px 0}
.row+.row{border-top:1px solid var(--border)}
.k{color:var(--muted);white-space:nowrap}
.v{
  color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  word-break:break-all;text-align:right;
}
.brand{margin-top:26px;font-size:12px;color:var(--muted);letter-spacing:.02em}
.brand a{text-decoration:none}
.brand a:hover{text-decoration:underline}
.brand b{color:var(--accent);font-weight:700}
</style>"##;

pub fn render_challenge(
    tera: &Tera,
    template: &str,
    params: &ChallengePageParams,
) -> Result<String> {
    ensure!(
        !template.to_ascii_lowercase().contains("<script"),
        "challenge templates cannot include inline scripts"
    );
    let mut context = Context::new();
    context.insert("brand_name", &params.brand_name);
    context.insert("request_id", &params.request_id);
    context.insert("difficulty", &params.difficulty);
    context.insert("verify_endpoint", &params.verify_endpoint);
    context.insert("original_url", &params.original_url);
    context.insert("challenge_scripts", &challenge_scripts(params));
    let html = tera.render("challenge.html", &context)?;
    ensure!(
        html.contains("<script") && html.contains("computeProofOfWork"),
        "include challenge_scripts with the safe filter"
    );
    for id in REQUIRED_DOM_IDS {
        ensure!(
            html.contains(&format!("id=\"{id}\""))
                || html.contains(&format!("id='{id}'")),
            "missing challenge element {id}"
        );
    }
    ensure!(
        html.len() <= MAX_PAGE_BYTES,
        "rendered page exceeds 256 KiB"
    );
    Ok(html)
}

pub fn validate(scope: &str, status: i32, template: &str) -> Result<()> {
    ensure!(!template.trim().is_empty(), "empty page template");
    ensure!(
        template.len() <= MAX_PAGE_BYTES,
        "page template exceeds 256 KiB"
    );
    let mut tera = Tera::default();
    if scope == "challenge" {
        tera.add_raw_template("challenge.html", template)?;
        render_challenge(&tera, template, &ChallengePageParams::default())?;
        return Ok(());
    }
    let mut context = Context::new();
    ensure!(
        matches!(scope, "site" | "unmatched_host"),
        "unknown page scope"
    );
    if scope == "site" {
        tera.add_raw_template("_pw_style", PW_STYLE)?;
        for key in [
            "method",
            "path",
            "user_agent",
            "waf_rule",
            "waf_details",
            "retry_after",
        ] {
            context.insert(key, "preview");
        }
    }
    for key in [
        "host",
        "request_id",
        "error_message",
        "site_name",
        "client_ip",
        "timestamp",
        "upstream_name",
        "upstream_addr",
        "request_path",
        "request_host",
    ] {
        context.insert(key, "preview");
    }
    context.insert("error_code", &status);
    tera.add_raw_template("preview", template)?;
    let html = tera.render("preview", &context)?;
    ensure!(
        html.len() <= MAX_PAGE_BYTES,
        "rendered page exceeds 256 KiB"
    );
    Ok(())
}
