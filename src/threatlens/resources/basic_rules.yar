rule ThreatLens_UPX_Packer {
  meta:
    source = "ThreatLens Desktop"
    category = "packing"
  strings:
    $upx0 = "UPX0"
    $upx1 = "UPX1"
    $upx = "UPX!"
  condition:
    any of them
}

rule ThreatLens_MPRESS_Packer {
  meta:
    source = "ThreatLens Desktop"
    category = "packing"
  strings:
    $mpress1 = "MPRESS1"
    $mpress2 = "MPRESS2"
  condition:
    any of them
}
