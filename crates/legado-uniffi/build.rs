fn main() {
    uniffi::generate_scaffolding("src/legado_native.udl").expect("generate UniFFI scaffolding");
}
