{
	"targets": [ {
		"target_name":  "dtls",
		"sources": [ "src/dtls.cc" ],
		"include_dirs": [
			"<!(node -e \"require('nan')\")",
			"<(node_root_dir)/deps/openssl/openssl/include"
		]
	} ]
}
