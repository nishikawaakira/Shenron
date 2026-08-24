# Cross-telemetry benchmark status

Parser and source-capability implementation is complete and fixture-validated, but the real comparison is intentionally pending. The exact pinned `nuclei-templates` revision `48a4f865127cb9e6b113c6bb493c984978009fd4` was no longer available in the prior external checkout, and a fresh official clone did not expose that object. Running against a different branch would invalidate comparison with the frozen AWS WAF study.

Once the exact checkout or archive is supplied, run:

```bash
cargo run --bin webhunt-lab -- nuclei compare-telemetry \
  --templates /path/to/pinned/nuclei-templates \
  --revision 48a4f865127cb9e6b113c6bb493c984978009fd4 \
  --report comparison.json
```

The command fails fast if the template directory is absent. It evaluates AWS WAF, nginx combined, and Apache combined from the same static conversion and matcher requirements; header-dependent detections are intentionally unavailable to standard combined logs.
