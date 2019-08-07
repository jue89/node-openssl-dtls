{
	"targets": [ {
		"target_name": "dtls",
		"sources": [
			"src/init.cc",
			"src/helper.cc",
			"src/context.cc",
			"src/session.cc"
		],
		"include_dirs": [
			"<!(node -e \"require('nan')\")",
			"<(node_root_dir)/deps/openssl/openssl/include"
		]
	} ]
}
