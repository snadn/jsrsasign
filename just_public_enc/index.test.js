const pem = {"privateKey":"-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAMDiTLrq+KuHjaENP9ZLGG7bV5wg4UWnFPYwrNaYQ5ctIDNA3WBz\nDtlKDJvwUChCJsqT21i2yTKYLg0YCtF/D3MCAwEAAQJBAJWhuPa0fA7NTMDov2Il\nxaGSRUfYdgoL0QYfwqWDX8PxIroZ81Btfuq+5WatB9IYmS6KMfUKNH9oR7mnX5r7\niTECIQDza7CC5xoybFsIacNbXy719+UyaoORNrUjR/luygePeQIhAMraCkBEtDW3\nI9Dc+yjYR4viw1zQywaCS6E3F92sM39LAiAnpz9V07fcxvH9aN0+IT9RKlTX5aoR\nGcxgNvVXKuoYYQIhAIO3ny5qLkYu3D/ULfYwsgyAO3D6VsqsMmXFe2bCWVIPAiAg\nnCMsnSCNj7vsHU6sSTzOsB/aVPkG4uojq4oOOwzTlA==\n-----END RSA PRIVATE KEY-----","publicPem":"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMDiTLrq+KuHjaENP9ZLGG7bV5wg4UWn\nFPYwrNaYQ5ctIDNA3WBzDtlKDJvwUChCJsqT21i2yTKYLg0YCtF/D3MCAwEAAQ==\n-----END PUBLIC KEY-----"};

test('enc.custom', () => {
	const { RSAKey, pemtohex, hex2b64 } = require('./index.custom.js');
	const pubkeyObj = new RSAKey();
	pubkeyObj.readPKCS8PubKeyHex(pemtohex(pem.publicPem, "PUBLIC KEY"));
	const key = pubkeyObj.encryptOAEP('000000', "sha1");
	console.log(hex2b64(key));
});
test('enc', () => {
	const { RSAKey, pemtohex, hex2b64 } = require('./index.js');
	const pubkeyObj = new RSAKey();
	pubkeyObj.readPKCS8PubKeyHex(pemtohex(pem.publicPem, "PUBLIC KEY"));
	const key = pubkeyObj.encryptOAEP('000000', "sha1");
	console.log(hex2b64(key));
});
test('enc.min', () => {
	const { RSAKey, pemtohex, hex2b64 } = require('./index.min.js');
	const pubkeyObj = new RSAKey();
	pubkeyObj.readPKCS8PubKeyHex(pemtohex(pem.publicPem, "PUBLIC KEY"));
	const key = pubkeyObj.encryptOAEP('000000', "sha1");
	console.log(hex2b64(key));
});