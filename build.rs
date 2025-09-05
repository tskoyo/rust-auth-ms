fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic_prost_build::configure()
    //     .compile_well_known_types(true)
    //     .type_attribute(".authentication.SignInRequest", "#[derive(Debug, Clone)]")
    //     .type_attribute(".authentication.SignUpRequest", "#[derive(Debug, Clone)]")
    //     .type_attribute(".authentication.SignOutRequest", "#[derive(Debug, Clone)]")
    //     .compile_protos(
    //         &["proto/authentication.proto"], // list of proto files
    //         &["proto"],                      // include directories
    //     )?;
    tonic_prost_build::compile_protos("proto/authentication.proto")?;
    Ok(())
}
