# Local malformed request-target validation lab

This lab sends five static request targets only to containers bound to `127.0.0.1`. It never contacts an observed host or a production system.

The targets are the five combined-log synthetic-validation failures: `CVE-2023-33568`, `CVE-2023-39600`, `CVE-2023-32235`, `CVE-2015-6544`, and `CVE-2020-9054`.

Run an nginx container with `nginx.conf`, and an Apache HTTP Server container using its default Combined Log Format, each on a distinct loopback-only port. Then run:

```bash
python3 send_targets.py 18080  # nginx
python3 send_targets.py 18081  # Apache
```

Record status lines and the corresponding access-log entries. This lab is intentionally separate from the benchmark: it determines server acceptance and logging behavior, not CVE exploitability.

Measured results are in [results.md](results.md). The lab containers are disposable and must be stopped after each run.
