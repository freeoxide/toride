use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_proxy::nginx_config::{
    Directive, parse_nginx_config, parse_server_blocks, render_directive,
};

const BLOCK_COUNTS: [usize; 2] = [10, 100];
const DIRECTIVE_COUNTS: [usize; 2] = [5, 25];

fn synthetic_config(blocks: usize, directives: usize) -> String {
    let mut config = String::new();
    for block in 0..blocks {
        config.push_str("server {\n");
        config.push_str("    listen 80;\n");
        let _ = writeln!(config, "    server_name bench-{block}.example.com;");
        for directive in 0..directives {
            let _ = writeln!(
                config,
                "    add_header X-Bench-{directive} value-{directive};"
            );
        }
        config.push_str("    location / {\n        proxy_pass http://127.0.0.1:8080;\n    }\n");
        config.push_str("}\n");
    }
    config
}

fn round_trip(directives: &[Directive]) -> String {
    directives
        .iter()
        .map(|d| render_directive(d, 0))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn bench_nginx_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("nginx_parse");

    for blocks in BLOCK_COUNTS {
        for directives in DIRECTIVE_COUNTS {
            let config = synthetic_config(blocks, directives);

            let parsed = parse_nginx_config(&config).expect("synthetic config must parse");
            assert_eq!(parsed.len(), blocks, "one top-level server block each");
            let server_blocks = parse_server_blocks(&config).expect("server blocks");
            assert_eq!(server_blocks.len(), blocks);
            assert!(
                server_blocks
                    .iter()
                    .all(|b| b.directives.len() == directives + 3),
                "listen + server_name + {directives} headers + one location block"
            );
            let reparsed = parse_nginx_config(&round_trip(&parsed)).expect("round trip parses");
            assert_eq!(reparsed, parsed, "render must reproduce the parsed tree");

            group.bench_function(format!("parse/S{blocks}_L{directives}"), |b| {
                b.iter(|| parse_nginx_config(black_box(&config)).expect("parse"));
            });

            group.bench_function(format!("parse_and_extract/S{blocks}_L{directives}"), |b| {
                b.iter(|| {
                    let server_blocks =
                        parse_server_blocks(black_box(&config)).expect("server blocks");
                    black_box(server_blocks.len())
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_nginx_parse);
criterion_main!(benches);
