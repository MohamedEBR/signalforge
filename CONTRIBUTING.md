# Contributing

Create a focused branch and keep rule changes separate from unrelated engine
changes. New analytics require malicious and benign replay fixtures, documented
false positives, ATT&CK mappings, investigation steps, and no real secrets or
personal data.

Before opening a pull request, run:

```bash
make check
make benchmark
git diff --check
```

Explain the detection hypothesis, telemetry assumptions, expected operational
volume, evasion opportunities, and tuning performed. Security-sensitive changes
to normalization, matching, correlation, or response models should receive a
second reviewer.
