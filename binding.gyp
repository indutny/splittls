{
  "targets": [{
    "target_name": "splittls-engine",
    "include_dirs": [
      "<(node_root_dir)/deps/openssl/openssl/include",
    ],
    "libraries": [ "-lpthread" ],
    "sources": [
      "engine/splittls.c",
    ],
  }, {
    "target_name": "splittls-binding",
    "include_dirs": [
      "<(node_root_dir)/deps/openssl/openssl/include",
    ],
    "sources": [
      "src/splittls.cc",
    ],
  }],
}
