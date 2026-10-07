# Architecture

```text
CloudTrail JSON / AWS lookup
          |
          v
     Event loader
          |
          v
    Detection engine
          |
     +----+----+
     |         |
  Rule set   Context
     |         |
     +----+----+
          |
          v
   Alert formatter
      /       \
 console       JSON
```

`src/main.py` is the CLI entry point. `src/utils.py` loads events and creates stable alert identifiers. `src/rules.py` contains the 11 deterministic rules. `src/detector.py` evaluates events. `src/alerts.py` converts detections into analyst-friendly structured alerts. `src/cloudtrail.py` provides an optional boto3 integration point.

The offline path has no network dependency and is safe for demonstrations.
