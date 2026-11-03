# Migration provenance

SSH Log Analyzer began in
[`Nodir404/Cyber-Learning`](https://github.com/Nodir404/Cyber-Learning), under
`projects/ssh-log-analyzer/`.

The migration source is commit
[`f2b4cad957415549fe5b8a59f3c010f662c6d04a`](https://github.com/Nodir404/Cyber-Learning/commit/f2b4cad957415549fe5b8a59f3c010f662c6d04a),
after the JSON/HTML reports and authentication metadata changes were merged.

## History strategy

Import the public source repository with GitHub's repository importer, then
move the analyzer into the repository root in a separate commit. The original
commits and authors remain in the inherited history; their original paths can
be inspected there. This is a full-history import, not a filtered rewrite.
Earlier history therefore also contains the public learning notes and lab.
The current analyzer tree contains only this tool, its documentation, tests,
synthetic examples, license, and workflow.

The move leaves `analyzer.py`, `reports.py`, test modules, and sample logs
byte-for-byte unchanged. Documentation and CI paths are adapted to the new
root. The MIT license is retained.

## Validation before switching the source of truth

1. Confirm that the imported repository contains the source commit above.
2. Compare the moved Python files and sample logs with the source by Git blob hash.
3. Run `python3 -m unittest discover -s . -p 'test_*.py' -v`: 45 tests are expected.
4. Run the documented sample and confirm 3 successes, 4 failures, 4 IPs, and 3 skipped lines.
5. Run the burst sample and confirm the five-failure alert from `192.0.2.10`.
6. Check internal links and the dedicated CI on Python 3.10 and 3.13.
7. Only after the dedicated repository is verified, replace the old active copy
   in `Cyber-Learning` with a link to this repository. Notes and the lab remain there.

HTML visual review in a local browser remains a manual follow-up. Automated
tests cover its data, escaping, and offline structure; migration does not alter
the renderer.
