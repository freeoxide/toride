use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::TempDir;
use toride_proxy::config::ConfigManager;
use toride_proxy::paths::ProxyPaths;

const SITE_COUNTS: [usize; 2] = [10, 50];
const WRITES_PER_PASS: usize = 50;
const SITE_CONFIG_BYTES: usize = 384;

fn seeded_tree(site_count: usize) -> (TempDir, ProxyPaths) {
    let dir = TempDir::new().expect("site_apply tempdir");
    let paths = ProxyPaths::with_root(dir.path());
    std::fs::create_dir_all(&paths.nginx_sites_available).expect("sites-available dir");
    std::fs::create_dir_all(&paths.caddy_conf_dir).expect("caddy dir");
    let content = site_config(SITE_CONFIG_BYTES);
    for i in 0..site_count {
        let path = paths.nginx_site_path(&format!("seed-{i}.example.com"));
        std::fs::write(path, &content).expect("seed site");
    }
    std::fs::write(&paths.nginx_conf, "events {}\n").expect("nginx.conf");
    std::fs::write(&paths.caddyfile, "").expect("Caddyfile");
    (dir, paths)
}

fn site_config(min_bytes: usize) -> String {
    let mut config = String::from(
        "server {\n    listen 80;\n    server_name bench.example.com;\n    location / {\n        proxy_pass http://127.0.0.1:8080;\n    }\n",
    );
    let filler = "    add_header X-Bench-Filler 0123456789abcdef;\n";
    while config.len() < min_bytes {
        config.push_str(filler);
    }
    config.push_str("}\n");
    config
}

fn tree_bytes(root: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(md) = entry.metadata() {
                total += md.len();
            }
        }
    }
    total
}

fn apply_pass(manager: &ConfigManager, site_count: usize) {
    let content = site_config(SITE_CONFIG_BYTES);
    for write in 0..WRITES_PER_PASS {
        let domain = format!("seed-{}.example.com", write % site_count);
        manager
            .write_site_config(&domain, &content)
            .expect("write_site_config");
    }
}

fn bench_site_apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("site_apply");

    for site_count in SITE_COUNTS {
        let (dir, paths) = seeded_tree(site_count);
        let manager = ConfigManager::new(&paths);

        let before = tree_bytes(dir.path());
        apply_pass(&manager, site_count);
        let after = tree_bytes(dir.path());
        let written = after.saturating_sub(before);
        println!(
            "site_apply: {WRITES_PER_PASS} sequential write_site_config calls over {site_count} seeded sites wrote {written} net bytes to disk (site files plus per-file pre-mutation backups, pruned to the newest few)"
        );
        assert!(
            written > SITE_CONFIG_BYTES as u64,
            "the pass must persist at least one site rewrite and one backup snapshot"
        );

        group.bench_function(format!("write_site_config_x50/sites_{site_count}"), |b| {
            b.iter(|| apply_pass(black_box(&manager), black_box(site_count)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_site_apply);
criterion_main!(benches);
