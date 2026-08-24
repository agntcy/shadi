fn main() {
    shadi_telemetry::init("otel-smoke");

    tracing::info_span!("outside_runtime").in_scope(|| tracing::info!("sync path"));

    // shadictl runs async work after init; a span ending in that context must
    // not blow up the exporter.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        tracing::info_span!("inside_runtime").in_scope(|| tracing::info!("async path"));
    });

    shadi_telemetry::shutdown();
    println!("SMOKE OK");
}
