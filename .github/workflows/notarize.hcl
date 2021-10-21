apple_id {
  password = "@env:AC_PASSWORD"
}

notarize {
  path = "./release/nebula.dmg"
  bundle_id = "net.defined.nebula"
  staple = true
}