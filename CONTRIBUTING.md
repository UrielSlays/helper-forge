# Contributing

Hephaestus is air-gap-first and fail-closed. Contributions must preserve those
properties rather than treating them as deployment options.

Before submitting a change:

1. Run the standard-library test suite with `python -m unittest discover -s tests -t . -v`.
2. Add a red test for any correctness or security defect before its fix.
3. Keep runtime dependencies at zero unless a dependency has an offline
   acquisition and verification path.
4. Never make event payloads executable and never let a generated helper grant
   itself credentials, deployment authority, or a broader action set.
5. Version any schema or behavior change that can alter an artifact, verdict,
   or promotion decision.

Generated model files, private corpora, credentials, and run artifacts do not
belong in Git. Publish only deliberately reviewed fixtures and evidence.
