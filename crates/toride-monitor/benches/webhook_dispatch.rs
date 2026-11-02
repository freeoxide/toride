use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_monitor::alert::AlertDispatcher;
use toride_monitor::paths::MonitorPaths;
use toride_monitor::report::{AnomalyFinding, AnomalySeverity};
use toride_monitor::spec::AlertTarget;
use toride_runner::fake::FakeRunner;

const DISPATCHES_PER_ITERATION: usize = 4;

fn handle_request(mut stream: TcpStream) {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                seen.extend_from_slice(&chunk[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn spawn_responder() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local responder");
    let url = format!("http://{}/hook", listener.local_addr().expect("local addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_request(stream);
        }
    });
    url
}

fn bench_paths() -> MonitorPaths {
    MonitorPaths {
        iptables: PathBuf::from("/usr/sbin/iptables"),
        iptables_save: PathBuf::from("/usr/sbin/iptables-save"),
        conntrack: PathBuf::from("/usr/sbin/conntrack"),
        ss: PathBuf::from("/usr/bin/ss"),
        journalctl: PathBuf::from("/usr/bin/journalctl"),
        systemd_cat: PathBuf::from("/usr/bin/systemd-cat"),
    }
}

fn bench_finding() -> AnomalyFinding {
    AnomalyFinding::new(
        "anomaly.connection-volume",
        AnomalySeverity::Warning,
        "Too many outbound connections",
        "650",
        "500",
    )
}

fn bench_payload(finding: &AnomalyFinding) -> serde_json::Value {
    serde_json::json!({
        "id": finding.id,
        "severity": finding.severity.to_string(),
        "title": finding.title,
        "observed_value": finding.observed_value,
        "threshold": finding.threshold,
        "fix": finding.fix,
    })
}

fn bench_webhook_dispatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("webhook_dispatch_local");

    let url = spawn_responder();
    let paths = bench_paths();
    let runner = FakeRunner::new();
    let dispatcher = AlertDispatcher::new(&paths, &runner);
    let finding = bench_finding();
    let targets = vec![AlertTarget::Webhook {
        url: url.clone(),
        headers: Vec::new(),
    }];

    let reports = dispatcher.dispatch(&finding, &targets);
    assert!(
        reports[0].dispatched,
        "local responder must accept the dispatch: {:?}",
        reports[0].error
    );

    group.bench_function("per_dispatch_new_client", |b| {
        b.iter(|| {
            let mut ok_count = 0;
            for _ in 0..DISPATCHES_PER_ITERATION {
                let reports = dispatcher.dispatch(black_box(&finding), black_box(&targets));
                if reports[0].dispatched {
                    ok_count += 1;
                }
            }
            black_box(ok_count)
        });
    });

    group.bench_function("shared_client", |b| {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("shared client");
        let payload = bench_payload(&finding);
        b.iter(|| {
            let mut ok_count = 0;
            for _ in 0..DISPATCHES_PER_ITERATION {
                if let Ok(resp) = client.post(black_box(&url)).json(&payload).send()
                    && resp.status().is_success()
                {
                    ok_count += 1;
                }
            }
            black_box(ok_count)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_webhook_dispatch);
criterion_main!(benches);
