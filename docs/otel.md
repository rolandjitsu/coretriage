# OpenTelemetry output

coretriage emits crash telemetry as OpenTelemetry OTLP/JSON: a metric counter of faults
(`--format otel-metrics`) and one log event per distinct fault (`--format otel-logs`). This is the
schema those carry. Treat it as a stable contract - the attribute keys, metric name, and event
name are what dashboards and alerts match on, so they change only with a coretriage major version.

Output goes to stdout; coretriage stays offline, so you post it to an OTel Collector or any
OTLP/HTTP endpoint yourself (see the [README](../README.md#usage)).

## Resource and scope

- Resource `service.name`: `coretriage`.
- Instrumentation scope: name `coretriage`, version = the crate version.
- `timeUnixNano` is `0`, so the Collector stamps arrival time on ingest; this keeps a batch run
  deterministic.

## Metric

| field | value |
| --- | --- |
| name | `coretriage.faults` |
| type | Sum, monotonic, cumulative |
| unit | `{core}` |
| data point value | number of cores with this signature |

One data point per bucket (a single core is one point of value 1), attributed as below.

## Log event

One `LogRecord` per distinct fault:

| field | value |
| --- | --- |
| `event.name` | `coretriage.fault` |
| body | the signature label, e.g. `SIGSEGV in app!render_widget` |
| severity | `ERROR` for a signal, `WARN` for a hang |

## Attributes

Both the metric data points and the log records carry these, so a metric series joins to its
events:

| key | type | when present | meaning |
| --- | --- | --- | --- |
| `fault.signature` | string | always | BLAKE3 hex crash signature |
| `fault.kind` | string | always | `signal` or `hang` |
| `fault.signal` | int | signal faults | signal number (e.g. 11) |
| `fault.signal.name` | string | known signals | signal name (e.g. `SIGSEGV`) |
| `fault.function` | string | a frame resolved | top frame `module!function` |
| `fault.build_id` | string | top module's build-id known | GNU build-id, lowercase hex |
| `fault.count` | int | log records only | cores in the bucket (the metric carries this as the data-point value) |

The attributes use a `fault.*` namespace rather than OTel's `exception.*` convention: a fatal
signal or a hang is not a language exception, and the signature and build-id have no `exception.*`
equivalent.
