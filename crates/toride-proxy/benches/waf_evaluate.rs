use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_proxy::waf::{WafConfig, WafDecision, WafEngine, WafMode, WafRequest};

fn prevention_engine() -> WafEngine {
    let config = WafConfig::new()
        .enabled()
        .prevention()
        .with_default_rules()
        .expect("built-in rules must compile");
    WafEngine::new(config).expect("default config must validate")
}

fn benign_request() -> WafRequest {
    WafRequest::new("GET", "/index.html").query("page=2&lang=en")
}

fn sqli_request() -> WafRequest {
    WafRequest::new("GET", "/search").query("q=1' OR '1'='1")
}

fn xss_request() -> WafRequest {
    WafRequest::new("POST", "/comment").body("<script>alert(1)</script>")
}

fn bench_waf_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("waf_evaluate");

    let engine = prevention_engine();
    let benign = benign_request();
    let sqli = sqli_request();
    let xss = xss_request();

    assert_eq!(engine.evaluate(&benign), WafDecision::Allow);
    assert!(engine.evaluate(&sqli).is_blocked(), "SQLi query must block");
    assert!(engine.evaluate(&xss).is_blocked(), "XSS body must block");
    assert_eq!(engine.config().mode, WafMode::Prevention);

    group.bench_function("evaluate/benign", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&benign))));
    });

    group.bench_function("evaluate/sqli_query", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&sqli))));
    });

    group.bench_function("evaluate/xss_body", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&xss))));
    });

    group.bench_function("evaluate/mixed_trio", |b| {
        b.iter(|| {
            let mut blocked = 0;
            for request in [&benign, &sqli, &xss] {
                if engine.evaluate(request).is_blocked() {
                    blocked += 1;
                }
            }
            black_box(blocked)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_waf_evaluate);
criterion_main!(benches);
