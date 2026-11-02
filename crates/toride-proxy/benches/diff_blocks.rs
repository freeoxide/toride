use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use toride_proxy::diff::{changed_blocks, diff_summary, removed_blocks};
use toride_proxy::spec::ServerBlock;

const BLOCK_COUNTS: [usize; 3] = [50, 250, 1000];

struct DiffFixture {
    current: Vec<ServerBlock>,
    desired: Vec<ServerBlock>,
    added: usize,
    modified: usize,
    removed: usize,
}

fn block(name: &str, upstream: u16) -> ServerBlock {
    ServerBlock::new(
        format!("{name}.example.com"),
        80,
        format!("127.0.0.1:{upstream}"),
    )
    .with_directive("proxy_set_header X-Backend bench")
}

fn diff_fixture(blocks: usize) -> DiffFixture {
    let removed = blocks / 20;
    let added = blocks / 20;
    let modified = (0..blocks - removed)
        .filter(|i| (i + 1).is_multiple_of(10))
        .count();

    let current: Vec<ServerBlock> = (0..blocks)
        .map(|i| {
            let offset = u16::try_from(i % 100).expect("offset below 100 fits u16");
            block(&format!("site-{i}"), 8000 + offset)
        })
        .collect();

    let mut desired: Vec<ServerBlock> = current
        .iter()
        .enumerate()
        .filter(|(i, _)| *i < blocks - removed)
        .map(|(i, c)| {
            if (i + 1).is_multiple_of(10) {
                block(&format!("site-{i}"), 9000)
            } else {
                c.clone()
            }
        })
        .collect();
    for i in 0..added {
        desired.push(block(&format!("new-{i}"), 7000));
    }

    DiffFixture {
        current,
        desired,
        added,
        modified,
        removed,
    }
}

fn bench_diff_blocks(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_blocks");

    for blocks in BLOCK_COUNTS {
        let fixture = diff_fixture(blocks);

        let changed = changed_blocks(&fixture.current, &fixture.desired);
        let removed = removed_blocks(&fixture.current, &fixture.desired);
        assert_eq!(
            changed.len(),
            fixture.modified + fixture.added,
            "modified plus added blocks are changed"
        );
        assert_eq!(
            removed.len(),
            fixture.removed + fixture.modified,
            "dropped blocks plus superseded modified blocks are removed"
        );
        let summary = diff_summary(&fixture.current, &fixture.desired);
        assert!(summary.starts_with("Added: new-0.example.com"), "{summary}");
        assert!(summary.contains("Removed: site-"), "{summary}");
        assert!(summary.contains("Modified: site-"), "{summary}");

        group.bench_function(format!("changed_blocks/n{blocks}"), |b| {
            b.iter(|| {
                black_box(
                    changed_blocks(black_box(&fixture.current), black_box(&fixture.desired)).len(),
                )
            });
        });

        group.bench_function(format!("removed_blocks/n{blocks}"), |b| {
            b.iter(|| {
                black_box(
                    removed_blocks(black_box(&fixture.current), black_box(&fixture.desired)).len(),
                )
            });
        });

        group.bench_function(format!("diff_summary/n{blocks}"), |b| {
            b.iter(|| {
                black_box(diff_summary(
                    black_box(&fixture.current),
                    black_box(&fixture.desired),
                ))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_diff_blocks);
criterion_main!(benches);
