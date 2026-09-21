# Drop-in platforms

Beacon loads plugins that export a `PLUGIN` object with:

- `spec`: a `FetcherSpec`
- `collect(ctx)`: returns `CollectResult`

## FetcherSpec

```python
from beacon.plugins.spec import FetcherSpec

spec = FetcherSpec(
    name="echo",
    version="0.1.0",
    description="Example platform",
    category="example",
    scf_targets=("GOV-01",),
    tools=(),
)
```

`scf_targets` is how `beacon collect --target IAC-01` selects overlapping fetchers. A plugin is selected when a declared target equals the requested id, is a parent/child (IAC-01 vs IAC-01.1), or shares the SCF family code.

## collect()

```python
from beacon.plugins.spec import CollectContext, CollectResult

def collect(self, ctx: CollectContext) -> CollectResult:
    return CollectResult(
        ok=True,
        mode="live",          # live | fixture | live_failed
        payload={"source": "echo", "message": ctx.target or "hello"},
        scf_targets=(ctx.target,) if ctx.target else self.spec.scf_targets,
    )
```

Rules:

- Export `PLUGIN` at module level.
- Do not rewrite a live failure as a fixture. Return `mode="live_failed"` and `ok=False`.
- The engine seals `payload` on the witness chain and writes a Merkle/TSA checkpoint.
- `scf_targets` on the result is the seal list. Pass `()` when the run must not name a control. Leave it unset to use `spec.scf_targets`.

## Load path

Set `BEACON_PLUGIN_PATH` to a file or a directory of `*.py` files (path separator is `os.pathsep`).

```bash
export BEACON_PLUGIN_PATH=./examples/echo_platform.py
beacon plugins
beacon collect --plugin echo
```

Builtin inspectors (`aws.inspector`, `azure.inspector`, `gcp.inspector`) are the same `CloudInspectorPlugin` class with a per-cloud profile.

`aws.lake.logs` reads the evidence-lake logging bucket (`s3-access-logs/` and `cloudtrail/`). It seals observations and findings on **IAC-01**. Raw AWS objects stay in the logging bucket. Set `BEACON_LOGS_BUCKET` for `--live`. With no bucket, collect uses the fixture. A live read failure stays `live_failed`.

See [examples/echo_platform.py](../examples/echo_platform.py).
