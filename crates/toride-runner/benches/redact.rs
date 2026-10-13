use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use toride_runner::CommandSpec;
use toride_runner::display::{display_command_for_log, display_env_summary, redact_output};
use toride_runner::redact::{REDACT_FLAGS, redact_args};

const RESTIC_ARGS: [&str; 12] = [
    "-v",
    "--repo",
    "s3:https://s3.eu-central-1.amazonaws.com/backups-web",
    "--password-command",
    "cat /etc/restic/secret",
    "backup",
    "/srv/www",
    "/var/lib/postgresql",
    "--exclude",
    "*.tmp",
    "--tag",
    "daily",
];

const DOCTL_ARGS: [&str; 28] = [
    "compute",
    "droplet",
    "create",
    "web-01",
    "--region",
    "fra1",
    "--image",
    "ubuntu-24-04-x64",
    "--size",
    "s-1vcpu-1gb",
    "--enable-monitoring",
    "--enable-ipv6",
    "--tag-name",
    "web",
    "--tag-name",
    "prod",
    "--vpc-uuid",
    "9f3e2a6c-1111-4b57-9c2d-6d0e7f8a9b0c",
    "--ssh-keys",
    "20330571",
    "--user-data-file",
    "/etc/toride/cloud-init.yaml",
    "--wait",
    "--access-token",
    "dop_v1_9f3e61e84b0d7a4f6c31ad51e07b9c8d3",
    "--api-key=sk_live_51H8k2mQ7xVpLd4nR9wZ",
    "--output",
    "json",
];

const ENV_12: [(&str, &str); 12] = [
    ("DO_ACCESS_TOKEN", "dop_v1_env_9f3e61e84b0d7a4f"),
    ("GITHUB_TOKEN", "ghp_env_27HkL5mNpQ8rStUvWx"),
    ("DEPLOY_PASSWORD", "env-hunter2-corral"),
    ("SSH_KEY_PASSPHRASE", "env-passphrase-mist-921"),
    ("PROD_API_KEY", "env-api-key-larkin-482"),
    ("AWS_SECRET_ACCESS_KEY", "env-aws-secret-feldspar-77"),
    (
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    ),
    ("HOME", "/root"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("RUST_LOG", "toride=info,runner=debug"),
    ("TORIDE_PROFILE", "vps"),
];

const WG_STDIN_CONFIG: &str = "[Interface]\nPrivateKey = \
yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4=\nListenPort = 51820\n[Peer]\nPresharedKey = \
SyntaxMPHJq1+DSEyFjQEZcsTQnMkk5dMtHOdPzTQw2c=\nAllowedIPs = 10.0.0.2/32\nEndpoint = \
203.0.113.7:51820\n";

const FAILED_DEPLOY_LINE: &str = "time=\"2026-10-13T08:31:04Z\" level=error msg=\"upload failed \
for /srv/www/site.tar.zst: context deadline exceeded\" attempt=3 of 3\n";

fn multi_secret_spec() -> CommandSpec {
    CommandSpec::new("doctl")
        .args(DOCTL_ARGS)
        .envs(ENV_12)
        .stdin(WG_STDIN_CONFIG)
        .redact(true)
}

fn stdin_bytes_spec() -> CommandSpec {
    CommandSpec::new("wg")
        .args(["setconf", "wg0", "/dev/stdin"])
        .stdin_bytes(WG_STDIN_CONFIG.as_bytes().to_vec())
        .redact(true)
}

fn failed_deploy_stderr() -> String {
    let mut text = String::with_capacity(4096);
    for _ in 0..12 {
        text.push_str(FAILED_DEPLOY_LINE);
    }
    text.push_str(
        "doctl: POST https://api.digitalocean.com/v2/droplets rejected token \
         dop_v1_9f3e61e84b0d7a4f6c31ad51e07b9c8d3\n",
    );
    text.push_str("curl: key sk_live_51H8k2mQ7xVpLd4nR9wZ was revoked upstream\n");
    text.push_str("vault: env token dop_v1_env_9f3e61e84b0d7a4f expired at 2026-10-12T00:00:00Z\n");
    text.push_str("git: credential helper rejected ghp_env_27HkL5mNpQ8rStUvWx\n");
    text.push_str("sudo: pam_unix password check failed for env-hunter2-corral\n");
    text.push_str("ssh-add: bad passphrase env-passphrase-mist-921, try again\n");
    text.push_str("gateway: invalid api key env-api-key-larkin-482 for tenant prod\n");
    text.push_str("s3: signature mismatch with secret env-aws-secret-feldspar-77\n");
    text.push_str(
        "wg: Line unrecognized: 'PrivateKey = \
         yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4='\n",
    );
    text.push_str(
        "wg: Line unrecognized: 'PresharedKey = \
         SyntaxMPHJq1+DSEyFjQEZcsTQnMkk5dMtHOdPzTQw2c='\n",
    );
    text
}

fn assert_fixture_shape() {
    let restic: Vec<String> = RESTIC_ARGS.iter().map(|a| (*a).to_owned()).collect();
    let redacted = redact_args(&restic, REDACT_FLAGS);
    assert_eq!(redacted.len(), 12);
    assert_eq!(redacted[3], "--password-command");
    assert_eq!(redacted[4], "***");
    assert_eq!(redacted[9], "*.tmp");

    let doctl: Vec<String> = DOCTL_ARGS.iter().map(|a| (*a).to_owned()).collect();
    let redacted = redact_args(&doctl, REDACT_FLAGS);
    assert_eq!(redacted.len(), 28);
    assert_eq!(redacted[23], "--access-token");
    assert_eq!(redacted[24], "***");
    assert_eq!(redacted[25], "--api-key=***");
    assert_eq!(
        redacted[19], "20330571",
        "--ssh-keys must not match the --ssh-key redaction flag"
    );

    let display_spec = CommandSpec::new("doctl").args(DOCTL_ARGS);
    let forced = display_command_for_log(&display_spec, true);
    assert!(forced.contains("--access-token ***"));
    assert!(forced.contains("--api-key=***"));
    assert!(!forced.contains("dop_v1_9f3e61e84b0d7a4f6c31ad51e07b9c8d3"));
    let raw = display_command_for_log(&display_spec, false);
    assert!(raw.contains("dop_v1_9f3e61e84b0d7a4f6c31ad51e07b9c8d3"));

    let env_spec = CommandSpec::new("deploy-hook").envs(ENV_12);
    let summary = display_env_summary(&env_spec);
    assert!(summary.contains("DO_ACCESS_TOKEN=***"));
    assert!(summary.contains("AWS_SECRET_ACCESS_KEY=***"));
    assert!(summary.contains("PATH=/usr/local/sbin"));
    assert!(!summary.contains("env-hunter2-corral"));

    let text = failed_deploy_stderr();
    let scrubbed = redact_output(&multi_secret_spec(), &text);
    assert!(!scrubbed.contains("dop_v1_9f3e61e84b0d7a4f6c31ad51e07b9c8d3"));
    assert!(!scrubbed.contains("sk_live_51H8k2mQ7xVpLd4nR9wZ"));
    assert!(!scrubbed.contains("env-aws-secret-feldspar-77"));
    assert!(!scrubbed.contains("yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4="));
    assert!(scrubbed.contains("***"));
    assert!(scrubbed.contains("context deadline exceeded"));

    let bytes_scrubbed = redact_output(&stdin_bytes_spec(), &text);
    assert!(
        !bytes_scrubbed.contains("yAnz5TF+lXXJte14tji3zsMNmPaKj7jMEumQzxRjZn4="),
        "stdin_bytes private key must be scrubbed (foundations-5): {bytes_scrubbed}"
    );
    assert!(
        !bytes_scrubbed.contains("SyntaxMPHJq1+DSEyFjQEZcsTQnMkk5dMtHOdPzTQw2c="),
        "stdin_bytes preshared key must be scrubbed (foundations-5): {bytes_scrubbed}"
    );
}

fn bench_redact(c: &mut Criterion) {
    assert_fixture_shape();

    let restic_args: Vec<String> = RESTIC_ARGS.iter().map(|a| (*a).to_owned()).collect();
    let doctl_args: Vec<String> = DOCTL_ARGS.iter().map(|a| (*a).to_owned()).collect();
    let display_spec = CommandSpec::new("doctl").args(DOCTL_ARGS);
    let env_spec = CommandSpec::new("deploy-hook").envs(ENV_12);
    let multi_spec = multi_secret_spec();
    let bytes_spec = stdin_bytes_spec();
    let stderr_text = failed_deploy_stderr();

    let mut group = c.benchmark_group("redact");

    group.bench_function("redact_args/restic_12", |b| {
        b.iter(|| redact_args(black_box(&restic_args), black_box(REDACT_FLAGS)));
    });

    group.bench_function("redact_args/doctl_28", |b| {
        b.iter(|| redact_args(black_box(&doctl_args), black_box(REDACT_FLAGS)));
    });

    group.bench_function("display_command_for_log/redact_logs_on/doctl_28", |b| {
        b.iter(|| display_command_for_log(black_box(&display_spec), true));
    });

    group.bench_function("display_command_for_log/redact_logs_off/doctl_28", |b| {
        b.iter(|| display_command_for_log(black_box(&display_spec), false));
    });

    group.bench_function("display_env_summary/multi_key_env_12", |b| {
        b.iter(|| display_env_summary(black_box(&env_spec)));
    });

    group.finish();

    let mut scrub = c.benchmark_group("redact_output");
    scrub.throughput(Throughput::Bytes(stderr_text.len() as u64));

    scrub.bench_function("args_env_stdin_multi_secret_2k", |b| {
        b.iter(|| redact_output(black_box(&multi_spec), black_box(&stderr_text)));
    });

    scrub.bench_function("stdin_bytes_spec_2k", |b| {
        b.iter(|| redact_output(black_box(&bytes_spec), black_box(&stderr_text)));
    });

    scrub.finish();
}

criterion_group!(benches, bench_redact);
criterion_main!(benches);
