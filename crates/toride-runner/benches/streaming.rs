use std::hint::black_box;
use std::time::Duration;

use async_trait::async_trait;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_runner::streaming::{AsyncStreamingRunner, CommandEvent, CommandEventSink};
use toride_runner::{CommandSpec, Result, TokioRunner};

const LINES_20K: usize = 20_000;

const LINES_100K: usize = 100_000;

const NEWLINE_FREE_BYTES: usize = 512 * 1024;

const SAMPLE_SIZE: usize = 30;

const MEASUREMENT_TIME: Duration = Duration::from_secs(2);

const WARM_UP_TIME: Duration = Duration::from_millis(500);

#[derive(Default)]
struct CountingSink {
    stdout_chunk_bytes: usize,
    stderr_chunk_bytes: usize,
    stdout_lines: usize,
    stderr_lines: usize,
    events: usize,
}

#[async_trait]
impl CommandEventSink for CountingSink {
    async fn on_event(&mut self, event: CommandEvent) -> Result<()> {
        match event {
            CommandEvent::StdoutChunk(bytes) => self.stdout_chunk_bytes += bytes.len(),
            CommandEvent::StderrChunk(bytes) => self.stderr_chunk_bytes += bytes.len(),
            CommandEvent::StdoutLine(_) => self.stdout_lines += 1,
            CommandEvent::StderrLine(_) => self.stderr_lines += 1,
            CommandEvent::Started { .. } | CommandEvent::Exited { .. } => {}
        }
        self.events += 1;
        Ok(())
    }
}

fn seq_spec(n: usize) -> CommandSpec {
    let last = n.to_string();
    CommandSpec::new("seq").args(["1", last.as_str()])
}

fn newline_free_spec(bytes: usize) -> CommandSpec {
    let size = bytes.to_string();
    CommandSpec::new("head").args(["-c", size.as_str(), "/dev/zero"])
}

fn seq_expected_bytes(n: usize) -> usize {
    (1..=n).map(|i| i.to_string().len() + 1).sum()
}

fn assert_fixture_shape(rt: &tokio::runtime::Runtime) {
    let runner = TokioRunner;

    let mut sink = CountingSink::default();
    let output = rt
        .block_on(runner.run_streaming(&seq_spec(LINES_20K), &mut sink))
        .expect("seq streams");
    assert!(output.success);
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(sink.stdout_lines, LINES_20K);
    assert_eq!(sink.stdout_chunk_bytes, seq_expected_bytes(LINES_20K));
    assert_eq!(sink.stderr_chunk_bytes, 0);

    let mut sink = CountingSink::default();
    let output = rt
        .block_on(runner.run_streaming(&newline_free_spec(NEWLINE_FREE_BYTES), &mut sink))
        .expect("head streams");
    assert!(output.success);
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        sink.stdout_lines, 1,
        "newline-free stream must flush exactly one trailing partial line at EOF"
    );
    assert_eq!(sink.stdout_chunk_bytes, NEWLINE_FREE_BYTES);
}

fn bench_streaming(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");
    assert_fixture_shape(&rt);

    let runner = TokioRunner;
    let spec_20k = seq_spec(LINES_20K);
    let spec_100k = seq_spec(LINES_100K);
    let spec_chunks = newline_free_spec(NEWLINE_FREE_BYTES);

    let mut group = c.benchmark_group("streaming");
    group.sample_size(SAMPLE_SIZE);
    group.measurement_time(MEASUREMENT_TIME);
    group.warm_up_time(WARM_UP_TIME);

    group.throughput(Throughput::Bytes(seq_expected_bytes(LINES_20K) as u64));
    group.bench_function("run_streaming/seq_lines_20k", |b| {
        b.iter(|| {
            let mut sink = CountingSink::default();
            let output = rt
                .block_on(runner.run_streaming(black_box(&spec_20k), &mut sink))
                .expect("streaming run succeeds");
            black_box((output.stdout.len(), sink.stdout_lines, sink.events));
        });
    });

    group.throughput(Throughput::Bytes(seq_expected_bytes(LINES_100K) as u64));
    group.bench_function("run_streaming/seq_lines_100k", |b| {
        b.iter(|| {
            let mut sink = CountingSink::default();
            let output = rt
                .block_on(runner.run_streaming(black_box(&spec_100k), &mut sink))
                .expect("streaming run succeeds");
            black_box((output.stdout.len(), sink.stdout_lines, sink.events));
        });
    });

    group.throughput(Throughput::Bytes(NEWLINE_FREE_BYTES as u64));
    group.bench_function("run_streaming/chunks_512k_newline_free", |b| {
        b.iter(|| {
            let mut sink = CountingSink::default();
            let output = rt
                .block_on(runner.run_streaming(black_box(&spec_chunks), &mut sink))
                .expect("streaming run succeeds");
            black_box((output.stdout.len(), sink.stdout_chunk_bytes, sink.events));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_streaming);
criterion_main!(benches);
