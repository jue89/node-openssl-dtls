{
	"targets": [ {
		"target_name":  "dtls",
		"sources": [ "src/dtls.cc" ],
		"include_dirs": [ "<!(node -e \"require('nan')\")" ],
		"libraries": [ "<!@(pkg-config --libs-only-l --silence-errors libssl)" ]
	} ]
}
