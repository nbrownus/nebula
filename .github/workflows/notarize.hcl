source = ["./release/nebula"]
bundle_id = "net.defined.nebula"

apple_id {
  password = "@env:AC_PASSWORD"
}

sign {
  application_identity = "10BC1FDDEB6CE753550156C0669109FAC49E4D1E"
}

dmg {
  output_path = "./nebula.dmg"
  volume_name = "nebula"
}