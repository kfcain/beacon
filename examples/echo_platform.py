"""Example drop-in platform. Load with BEACON_PLUGIN_PATH."""

from __future__ import annotations

from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec


class EchoPlugin:
    spec = FetcherSpec(
        name="echo",
        version="0.1.0",
        description="Example drop-in platform that echoes the collect context.",
        category="example",
        scf_targets=("GOV-02",),
        tools=(),
    )

    def collect(self, ctx: CollectContext) -> CollectResult:
        payload = {
            "source": "echo",
            "mode": "live",
            "target": ctx.target,
            "message": ctx.target or "hello",
        }
        return CollectResult(
            ok=True,
            mode="live",
            payload=payload,
            scf_targets=(ctx.target,) if ctx.target else self.spec.scf_targets,
        )


PLUGIN = EchoPlugin()
