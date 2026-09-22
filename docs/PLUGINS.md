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

## Load path

Set `BEACON_PLUGIN_PATH` to a file or a directory of `*.py` files (path separator is `os.pathsep`).

```bash
export BEACON_PLUGIN_PATH=./examples/echo_platform.py
beacon plugins
beacon collect --plugin echo
```

Builtin inspectors (`aws.inspector`, `azure.inspector`, `gcp.inspector`) are the same `CloudInspectorPlugin` class with a per-cloud profile.

Builtin `scf.catalog.offline` verifies the slim SCF 2026.2 catalog pin. It does not fetch live HackIDLE. See [SCF_CATALOG.md](SCF_CATALOG.md).

```bash
beacon collect --plugin scf.catalog.offline --fixture
```

CRA Article 14 early-warning packing is a drop-in, not a builtin:

```bash
export BEACON_PLUGIN_PATH=./examples/cra_art14_early_warning.py
beacon collect --plugin cra.art14.early_warning --fixture
```

KEV is a signal only. See [CRA_ART14.md](CRA_ART14.md), [examples/cra_art14_early_warning.py](../examples/cra_art14_early_warning.py), and [examples/echo_platform.py](../examples/echo_platform.py).
