//! Rendering functions for proxy configuration files.
//!
//! Generates Nginx server blocks, Caddyfiles, and security header snippets
//! from typed specifications.

use crate::nginx_headers::SecurityHeaders;
use crate::spec::{ProxySpec, ServerBlock};

/// Render a single Nginx server block from a [`ServerBlock`] spec.
///
/// Produces a complete `server { ... }` block including listen directive,
/// `server_name`, TLS settings (if configured), and `proxy_pass` to upstream.
///
/// # Example
///
/// ```
/// use toride_proxy::render::render_nginx_server_block;
/// use toride_proxy::spec::ServerBlock;
///
/// let block = ServerBlock::new("example.com", 80, "127.0.0.1:3000");
/// let config = render_nginx_server_block(&block);
/// assert!(config.contains("server_name example.com"));
/// assert!(config.contains("proxy_pass http://127.0.0.1:3000"));
/// ```
pub fn render_nginx_server_block(block: &ServerBlock) -> String {
    render_nginx_server_block_inner(block, false, None)
}

/// Render a server block, optionally emitting the modern `http2 on;`
/// directive (nginx 1.25.1+) after the listen lines of TLS blocks and
/// splicing `prepend_directives` (one directive per line) between the proxy
/// location block and the caller's extra directives.
///
/// The `http2` listen parameter has been deprecated since nginx 1.25.1, so
/// HTTP/2 is expressed as its own directive and only when the caller's spec
/// asked for it.
fn render_nginx_server_block_inner(
    block: &ServerBlock,
    http2: bool,
    prepend_directives: Option<&str>,
) -> String {
    let mut lines = Vec::new();

    // Server block open
    lines.push("server {".to_string());

    // Listen directive
    if block.tls.is_some() {
        lines.push(format!("    listen {} ssl;", block.listen_port));
        lines.push(format!("    listen [::]:{} ssl;", block.listen_port));
        if http2 {
            lines.push("    http2 on;".to_string());
        }
    } else {
        lines.push(format!("    listen {};", block.listen_port));
        lines.push(format!("    listen [::]:{};", block.listen_port));
    }

    // Server name
    lines.push(format!("    server_name {};", block.server_name));

    // TLS configuration
    if let Some(tls) = &block.tls {
        lines.push(String::new());
        lines.push("    # TLS configuration".into());
        lines.push(format!("    ssl_certificate {};", tls.cert_path));
        lines.push(format!("    ssl_certificate_key {};", tls.key_path));

        if let Some(chain) = &tls.chain_path {
            lines.push(format!("    ssl_trusted_certificate {chain};"));
        }

        if tls.ocsp_stapling {
            lines.push("    ssl_stapling on;".into());
            lines.push("    ssl_stapling_verify on;".into());
        }
    }

    // Proxy pass
    lines.push(String::new());
    lines.push("    # Proxy configuration".into());
    lines.push("    location / {".to_string());
    lines.push(format!("        proxy_pass http://{};", block.upstream));
    lines.push("        proxy_http_version 1.1;".into());
    lines.push("        proxy_set_header Upgrade $http_upgrade;".into());
    lines.push("        proxy_set_header Connection \"upgrade\";".into());
    lines.push("        proxy_set_header Host $host;".into());
    lines.push("        proxy_set_header X-Real-IP $remote_addr;".into());
    lines.push("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;".into());
    lines.push("        proxy_set_header X-Forwarded-Proto $scheme;".into());
    lines.push("    }".into());

    // Spliced security headers (or other caller directives), then any extra
    // directives, before the closing brace.
    if let Some(directives) = prepend_directives {
        for directive in directives.lines() {
            lines.push(format!("    {directive}"));
        }
    }

    // Extra directives
    for directive in &block.extra_directives {
        lines.push(format!("    {directive}"));
    }

    // Server block close
    lines.push("}".to_string());

    lines.join("\n")
}

/// Render a single Nginx server block with security headers injected.
///
/// This wires [`SecurityHeaders::to_nginx_directives`] into the rendered block
/// so generated configs actually carry the configured security headers. The
/// directives are placed after the proxy `location` block and before any extra
/// directives, matching the layout operators expect.
///
/// Pass `None` to render without security headers (equivalent to
/// [`render_nginx_server_block`]).
pub fn render_nginx_server_block_with_headers(
    block: &ServerBlock,
    headers: Option<&SecurityHeaders>,
) -> String {
    let Some(headers) = headers else {
        return render_nginx_server_block(block);
    };

    let directives = headers.to_nginx_directives();
    if directives.is_empty() {
        return render_nginx_server_block(block);
    }

    render_nginx_server_block_inner(block, false, Some(&directives))
}

/// Render a complete Caddyfile from a [`ProxySpec`].
///
/// Produces Caddy-format configuration for all server blocks in the spec.
/// Each site address is explicit so plaintext blocks cannot silently pick up
/// Caddy's auto-HTTPS: a block without TLS renders as `http://host[:port]`,
/// and a TLS block carries its certificate paths via `tls <cert> <key>` plus
/// an explicit `:port` whenever the port differs from the scheme default.
///
/// # Example
///
/// ```
/// use toride_proxy::render::render_caddyfile;
/// use toride_proxy::spec::{ProxySpec, ServerBlock};
///
/// let spec = ProxySpec::builder()
///     .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000"))
///     .build();
/// let caddyfile = render_caddyfile(&spec);
/// assert!(caddyfile.contains("example.com"));
/// assert!(caddyfile.contains("reverse_proxy 127.0.0.1:3000"));
/// ```
pub fn render_caddyfile(spec: &ProxySpec) -> String {
    render_caddyfile_inner(spec, None)
}

/// Render a Caddyfile with security headers injected into every site block.
///
/// This is the Caddy counterpart of [`render_nginx_server_block_with_headers`]:
/// [`SecurityHeaders::to_caddyfile_directives`] lines are emitted after the
/// `reverse_proxy` directive. Pass `None` to render without headers
/// (equivalent to [`render_caddyfile`]).
pub fn render_caddyfile_with_headers(
    spec: &ProxySpec,
    headers: Option<&SecurityHeaders>,
) -> String {
    let Some(headers) = headers else {
        return render_caddyfile(spec);
    };
    let directives = headers.to_caddyfile_directives();
    if directives.is_empty() {
        return render_caddyfile(spec);
    }
    render_caddyfile_inner(spec, Some(&directives))
}

/// Caddy's default HTTPS and HTTP ports; addresses omit them explicitly.
const CADDY_HTTPS_PORT: u16 = 443;
const CADDY_HTTP_PORT: u16 = 80;

/// Format a block's Caddy site address from its TLS state and listen port.
fn caddy_site_address(block: &ServerBlock) -> String {
    match &block.tls {
        Some(_) if block.listen_port == CADDY_HTTPS_PORT => block.server_name.clone(),
        Some(_) => format!("{}:{}", block.server_name, block.listen_port),
        None if block.listen_port == CADDY_HTTP_PORT => {
            format!("http://{}", block.server_name)
        }
        None => format!("http://{}:{}", block.server_name, block.listen_port),
    }
}

fn render_caddyfile_inner(spec: &ProxySpec, header_directives: Option<&str>) -> String {
    let mut blocks = Vec::new();

    for block in &spec.server_blocks {
        let mut lines = Vec::new();

        lines.push(format!("{} {{", caddy_site_address(block)));

        if let Some(tls) = &block.tls {
            lines.push(format!("    tls {} {}", tls.cert_path, tls.key_path));
        }

        lines.push(format!("    reverse_proxy {}", block.upstream));

        if let Some(directives) = header_directives {
            for directive in directives.lines() {
                lines.push(format!("    {directive}"));
            }
        }

        for directive in &block.extra_directives {
            lines.push(format!("    {directive}"));
        }

        lines.push("}".to_string());
        blocks.push(lines.join("\n"));
    }

    blocks.join("\n\n")
}

/// Render common security headers as Nginx `add_header` directives.
///
/// Includes:
/// - `Strict-Transport-Security` (HSTS)
/// - `X-Content-Type-Options`
/// - `X-Frame-Options`
/// - `X-XSS-Protection`
/// - `Referrer-Policy`
/// - `Content-Security-Policy` (optional)
///
/// # Example
///
/// ```
/// use toride_proxy::render::render_security_headers;
///
/// let headers = render_security_headers(true, None);
/// assert!(headers.contains("Strict-Transport-Security"));
/// assert!(headers.contains("X-Content-Type-Options"));
/// ```
pub fn render_security_headers(include_hsts: bool, csp_policy: Option<&str>) -> String {
    let mut lines = Vec::new();

    lines.push("    # Security headers".into());

    if include_hsts {
        lines.push(
            "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
                .into(),
        );
    }

    lines.push("    add_header X-Content-Type-Options \"nosniff\" always;".into());
    lines.push("    add_header X-Frame-Options \"SAMEORIGIN\" always;".into());
    lines.push("    add_header X-XSS-Protection \"1; mode=block\" always;".into());
    lines.push("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;".into());

    if let Some(csp) = csp_policy {
        lines.push(format!(
            "    add_header Content-Security-Policy \"{csp}\" always;"
        ));
    }

    lines.join("\n")
}

/// Render a complete Nginx configuration from a [`ProxySpec`].
///
/// Produces all server blocks with security headers included. TLS blocks get
/// the modern `http2 on;` directive when the spec's `http2` flag is set.
pub fn render_nginx_config(spec: &ProxySpec) -> String {
    let mut blocks = Vec::new();

    for block in &spec.server_blocks {
        let block_config = render_nginx_server_block_inner(block, spec.http2, None);
        blocks.push(block_config);
    }

    blocks.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::TlsConfig;

    #[test]
    fn render_plaintext_server_block() {
        let block = ServerBlock::new("example.com", 80, "127.0.0.1:3000");
        let config = render_nginx_server_block(&block);

        assert!(config.contains("listen 80;"));
        assert!(config.contains("server_name example.com;"));
        assert!(config.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(!config.contains("ssl_certificate"));
    }

    #[test]
    fn render_tls_server_block() {
        let block =
            ServerBlock::new("example.com", 443, "127.0.0.1:3000").with_tls(TlsConfig::new(
                "example.com",
                "/etc/letsencrypt/live/example.com/fullchain.pem",
                "/etc/letsencrypt/live/example.com/privkey.pem",
            ));
        let config = render_nginx_server_block(&block);

        assert!(
            config.contains("listen 443 ssl;"),
            "the http2 listen parameter is deprecated since nginx 1.25.1: {config}"
        );
        assert!(
            !config.contains("http2"),
            "per-block rendering carries no spec context, so no http2 directive: {config}"
        );
        assert!(
            config.contains("ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;")
        );
        assert!(config.contains("ssl_stapling on;"));
    }

    /// The spec-level `http2` flag must render as the modern `http2 on;`
    /// directive, not the deprecated listen parameter.
    #[test]
    fn render_nginx_config_with_http2_flag_uses_the_directive() {
        let tls_block = ServerBlock::new("example.com", 443, "127.0.0.1:3000")
            .with_tls(TlsConfig::new("example.com", "/cert.pem", "/key.pem"));
        let plain_block = ServerBlock::new("plain.example.com", 80, "127.0.0.1:3000");

        let spec = ProxySpec::builder()
            .block(tls_block)
            .block(plain_block)
            .http2()
            .build();
        let config = render_nginx_config(&spec);

        assert!(
            config.contains("listen 443 ssl;") && config.contains("http2 on;"),
            "TLS blocks get the directive form: {config}"
        );
        let plain_start = config
            .find("server_name plain.example.com")
            .expect("present");
        let plain_section = &config[plain_start..];
        assert!(
            !plain_section.contains("http2"),
            "http2 applies to TLS blocks, not the plaintext one: {plain_section}"
        );
        assert!(!config.contains("ssl http2;"), "deprecated form: {config}");
    }

    #[test]
    fn render_nginx_config_without_http2_flag_omits_the_directive() {
        let spec =
            ProxySpec::builder()
                .block(
                    ServerBlock::new("example.com", 443, "127.0.0.1:3000")
                        .with_tls(TlsConfig::new("example.com", "/cert.pem", "/key.pem")),
                )
                .build();
        let config = render_nginx_config(&spec);
        assert!(config.contains("listen 443 ssl;"));
        assert!(!config.contains("http2"), "got: {config}");
    }

    #[test]
    fn render_caddyfile_basic() {
        let spec = ProxySpec::builder()
            .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000"))
            .build();

        let caddyfile = render_caddyfile(&spec);
        // No TLS configured: the address must say http:// explicitly so
        // Caddy's auto-HTTPS cannot redirect this site.
        assert!(caddyfile.contains("http://example.com:443 {"));
        assert!(caddyfile.contains("reverse_proxy 127.0.0.1:3000"));
    }

    /// A plaintext block on port 80 renders as `http://host`, so Caddy's
    /// auto-HTTPS cannot pick it up; a non-default port stays in the address.
    #[test]
    fn render_caddyfile_plaintext_addresses_are_explicit_http() {
        let spec = ProxySpec::builder()
            .block(ServerBlock::new("a.example.com", 80, "127.0.0.1:3000"))
            .block(ServerBlock::new("b.example.com", 8080, "127.0.0.1:3000"))
            .build();

        let caddyfile = render_caddyfile(&spec);
        assert!(
            caddyfile.contains("http://a.example.com {"),
            "default HTTP port is explicit about the scheme:\n{caddyfile}"
        );
        assert!(
            caddyfile.contains("http://b.example.com:8080 {"),
            "non-default plaintext port stays in the address:\n{caddyfile}"
        );
    }

    /// A TLS block keeps HTTPS (the Caddy default), names a non-443 port
    /// explicitly, and carries its certificate paths via `tls`.
    #[test]
    fn render_caddyfile_tls_blocks_name_certs_and_ports() {
        let spec = ProxySpec::builder()
            .block(
                ServerBlock::new("a.example.com", 443, "127.0.0.1:3000").with_tls(TlsConfig::new(
                    "a.example.com",
                    "/etc/letsencrypt/live/a/fullchain.pem",
                    "/etc/letsencrypt/live/a/privkey.pem",
                )),
            )
            .block(
                ServerBlock::new("b.example.com", 8443, "127.0.0.1:3000").with_tls(TlsConfig::new(
                    "b.example.com",
                    "/etc/letsencrypt/live/b/fullchain.pem",
                    "/etc/letsencrypt/live/b/privkey.pem",
                )),
            )
            .build();

        let caddyfile = render_caddyfile(&spec);
        assert!(
            caddyfile.contains("a.example.com {"),
            "443 is the HTTPS default and is omitted:\n{caddyfile}"
        );
        assert!(
            caddyfile.contains("b.example.com:8443 {"),
            "non-default TLS port stays in the address:\n{caddyfile}"
        );
        assert!(
            caddyfile.contains(
                "tls /etc/letsencrypt/live/a/fullchain.pem /etc/letsencrypt/live/a/privkey.pem"
            ),
            "configured certificate paths must reach the Caddyfile:\n{caddyfile}"
        );
        assert!(
            !caddyfile.contains("http://"),
            "TLS blocks stay on HTTPS:\n{caddyfile}"
        );
    }

    /// The header entry point must ship the same policy the nginx path ships.
    #[test]
    fn render_caddyfile_with_headers_injects_header_directives() {
        use crate::nginx_headers::SecurityHeaders;
        let spec = ProxySpec::builder()
            .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000"))
            .build();

        let plain = render_caddyfile(&spec);
        let with_headers = render_caddyfile_with_headers(&spec, Some(&SecurityHeaders::strict()));

        assert!(
            with_headers.contains("header Strict-Transport-Security \"max-age=63072000"),
            "HSTS must render as a caddy header directive:\n{with_headers}"
        );
        assert!(
            with_headers.contains("header Content-Security-Policy"),
            "CSP must render as a caddy header directive:\n{with_headers}"
        );
        assert_eq!(
            plain,
            render_caddyfile_with_headers(&spec, None),
            "None must equal the plain render"
        );
    }

    #[test]
    fn render_security_headers_with_hsts() {
        let headers = render_security_headers(true, None);
        assert!(headers.contains("Strict-Transport-Security"));
        assert!(headers.contains("X-Content-Type-Options"));
        assert!(headers.contains("X-Frame-Options"));
        assert!(!headers.contains("Content-Security-Policy"));
    }

    #[test]
    fn render_security_headers_with_csp() {
        let headers = render_security_headers(true, Some("default-src 'self'"));
        assert!(headers.contains("Content-Security-Policy"));
        assert!(headers.contains("default-src 'self'"));
    }

    #[test]
    fn render_block_with_headers_injects_directives() {
        use crate::nginx_headers::SecurityHeaders;
        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000");
        let rendered =
            render_nginx_server_block_with_headers(&block, Some(&SecurityHeaders::strict()));
        assert!(rendered.contains("Strict-Transport-Security"));
        assert!(rendered.contains("preload"));
        assert!(rendered.contains("server_name example.com;"));
    }

    #[test]
    fn render_block_with_none_headers_matches_plain() {
        let block = ServerBlock::new("example.com", 80, "127.0.0.1:3000");
        let plain = render_nginx_server_block(&block);
        let with_none = render_nginx_server_block_with_headers(&block, None);
        assert_eq!(plain, with_none);
    }
}
