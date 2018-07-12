#!/bin/bash
cat <<EOF > index.min.js
if (typeof module !== 'undefined') {
	var navigator = {
		userAgent: false
	};
	var window = exports;
}
EOF

cat ../ext/prng4-min.js ../ext/rng-min.js ../ext/cj/cryptojs-312-core-fix-min.js ../ext/cj/sha1_min.js ../ext/jsbn-min.js ../ext/jsbn2-min.js ../ext/base64-min.js ../ext/rsa-min.js ../min/base64x-1.1.min.js ../min/asn1hex-1.1.min.js ../min/crypto-1.1.min.js ../min/rsapem-1.1.min.js >> index.min.js

cat <<EOF >> index.min.js
if (typeof module !== 'undefined') {
	exports.pemtohex = pemtohex;
	exports.RSAKey = RSAKey;
}
EOF