{
  "targets": [{
    "target_name": "splittls",
    "include_dirs": [
      "<(node_root_dir)/deps/openssl/openssl/include",
    ],
    "sources": [
      "engine/splittls.c",
    ],
  }],
}
