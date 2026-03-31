fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()
        .expect("protoc binary not found — ensure protoc-bin-vendored is installed"));
    tonic_build::configure()
        .build_server(true)
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[allow(non_snake_case)]")
        .field_attribute(".", "#[allow(non_snake_case)]")
        .compile(
            &["../../protos/runtime.proto"],
            &["../../protos"],
        )?;
    Ok(())
}
