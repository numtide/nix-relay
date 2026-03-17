{
  nonce ? "default",
}:
derivation {
  name = "bench-dummy-${nonce}";
  system = builtins.currentSystem;
  builder = "/bin/sh";
  args = [
    "-c"
    "echo ${nonce} > $out"
  ];
}
