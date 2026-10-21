use std::hint::black_box;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_tailscale::TailscaleClient;
use toride_tailscale::status::NodeStatus;
use toride_tailscale::tailnet::TailnetTopology;

const PEER_COUNTS: [usize; 3] = [10, 100, 500];

const SAMPLE_SIZE: usize = 30;
const MEASUREMENT_TIME: Duration = Duration::from_secs(2);
const WARM_UP_TIME: Duration = Duration::from_millis(500);

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to build tokio runtime"))
}

fn status_document(peers: usize) -> serde_json::Value {
    let mut peer_map = serde_json::Map::with_capacity(peers);
    for index in 0..peers {
        let key = format!("nodekey:{index:040x}");
        peer_map.insert(
            key,
            serde_json::json!({
                "HostName": format!("bench-peer-{index:03}"),
                "TailscaleIPs": [
                    format!("100.64.0.{}", (index % 250) + 2),
                    format!("fd7a:115c:a1e0:b1a::{index:x}")
                ],
                "Online": index % 4 != 3,
                "ExitNodeOption": index % 50 == 7,
            }),
        );
    }
    serde_json::json!({
        "BackendState": "Running",
        "MagicDNSEnabled": true,
        "Self": {
            "HostName": "bench-self",
            "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0:b1a::1"],
        },
        "CurrentTailnet": { "Name": "bench-tailnet.example.ts.net" },
        "Peer": peer_map,
    })
}

fn status_text(peers: usize) -> String {
    serde_json::to_string(&status_document(peers)).expect("status document serializes")
}

fn oracle() {
    let document = status_document(PEER_COUNTS[0]);
    let node = NodeStatus::from_raw(document.clone());
    assert_eq!(node.name(), "bench-self");
    assert_eq!(node.tailnet(), "bench-tailnet.example.ts.net");
    let report = node.to_report();
    assert!(report.connected);

    let topology = TailnetTopology::from_status_json(&document).expect("topology parses");
    assert_eq!(topology.peers().len(), PEER_COUNTS[0]);
    assert_eq!(
        topology.online_peers().len(),
        8,
        "three of eleven nodes are offline"
    );
    assert_eq!(
        topology.exit_nodes().len(),
        1,
        "peer 7 offers exit-node service"
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&status_text(PEER_COUNTS[0])).expect("document round-trips");
    assert_eq!(parsed, document, "text and in-memory documents agree");
}

struct CountingServer {
    requests: Arc<AtomicUsize>,
    port: u16,
}

impl CountingServer {
    fn spawn(body: String) -> Self {
        let requests = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").expect("local listener binds");
        let port = listener.local_addr().expect("bound address").port();
        let counter = Arc::clone(&requests);
        let payload = Arc::new(body);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let payload = Arc::clone(&payload);
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        Self { requests, port }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

fn fetch_count_oracle() {
    let rt = runtime();
    let server = CountingServer::spawn(status_text(PEER_COUNTS[0]));
    let client = TailscaleClient::with_base_url(server.url());
    let report = rt.block_on(client.status_report()).expect("status answers");
    assert!(report.connected);
    let topology = rt.block_on(client.topology()).expect("topology answers");
    assert_eq!(topology.peers().len(), PEER_COUNTS[0]);
    assert_eq!(
        server.requests.load(Ordering::Relaxed),
        2,
        "status_report plus topology fetch the same status document twice today; the shared-fetch target is 1"
    );
}

fn status_parse(criterion: &mut Criterion) {
    oracle();
    fetch_count_oracle();

    let documents: Vec<(usize, String)> = PEER_COUNTS
        .iter()
        .map(|peers| (*peers, status_text(*peers)))
        .collect();

    let mut group = criterion.benchmark_group("status_parse");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    for (peers, text) in &documents {
        group.throughput(Throughput::Bytes(text.len() as u64));

        group.bench_function(format!("value_parse_{peers}_peers"), |b| {
            b.iter(|| {
                let document: serde_json::Value =
                    serde_json::from_str(black_box(text)).expect("document parses");
                black_box(
                    document
                        .get("Peer")
                        .and_then(|peers| peers.as_object())
                        .map_or(0, serde_json::Map::len),
                );
            });
        });

        group.bench_function(format!("node_status_report_{peers}_peers"), |b| {
            let document: serde_json::Value = serde_json::from_str(text).expect("document parses");
            b.iter(|| {
                let report = NodeStatus::from_raw(document.clone()).to_report();
                black_box(report.connected);
            });
        });

        group.bench_function(format!("topology_from_status_{peers}_peers"), |b| {
            let document: serde_json::Value = serde_json::from_str(text).expect("document parses");
            b.iter(|| {
                let topology =
                    TailnetTopology::from_status_json(black_box(&document)).expect("parses");
                black_box(topology.peers().len());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, status_parse);
criterion_main!(benches);
