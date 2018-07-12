#!/bin/bash
cat <<EOF > index.js
if (typeof module !== 'undefined') {
	var navigator = {
		userAgent: false
	};
	var window = exports;
}
EOF

cat ../ext/prng4.js ../ext/rng.js ../ext/cj/cryptojs-312-core-fix.js ../ext/cj/sha1.js ../ext/jsbn.js ../ext/jsbn2.js ../ext/base64.js ../ext/rsa.js ../src/base64x-1.1.js ../src/asn1hex-1.1.js ../src/crypto-1.1.js ../src/rsapem-1.1.js >> index.js

cat <<EOF >> index.js
if (typeof module !== 'undefined') {
	exports.pemtohex = pemtohex;
	exports.RSAKey = RSAKey;
}
EOF