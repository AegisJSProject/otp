import { describe, test } from 'node:test';
import { ok, deepStrictEqual, strictEqual } from 'node:assert';
import {
	createOTPAuthURI, parseOTPAuthURI, generateTOTP, generateSecret, verifyTOTP,
	secretToKey, deriveKeyFromPassword, base32EncodeKey,
} from '@aegisjsproject/otp';

const controller = new AbortController();
const signal = AbortSignal.any([AbortSignal.timeout(1000), controller.signal]);
const password = 'an example password';
const expected = 'VA3PK5ZWTOI352CLC3NYNH2XGCQUOJTE';
const salt = new Uint8Array([
	215, 160, 144, 104, 164,
	250, 128, 205,  35,  14,
	58,  17, 240,  87, 125,
	89
]); // Just some randomly generated but fixed salt

describe('Test OTP module', () => {
	test('Test generating secrets', { signal }, () => {
		try {
			strictEqual(generateSecret().length, 20, 'Secrets should have a length of 20 bytes by default.');
		} catch(err) {
			controller.abort(err);
		}
	});

	test('Verify generating and parsing of URIs', { signal }, async () => {
		try {
			const _secret = generateSecret();
			const uri = createOTPAuthURI({ label: 'Acme:user@example.com', issuer: 'Acme', secret: _secret });
			const { secret } = parseOTPAuthURI(uri);

			deepStrictEqual(secret, _secret, 'Parsed secret should deeply equal original.');
		} catch(err) {
			controller.abort(err);
		}
	});

	test('Verify generated TOTP codes', { signal }, async () => {
		try {
			const key = await secretToKey(generateSecret());
			const otp = await generateTOTP(key);
			const valid = await verifyTOTP(otp, key);

			ok(valid, 'Generated TOTP code should verify correctly.');
		} catch(err) {
			controller.abort(err);
		}
	});

	test('Verify password-based keys', { signal }, async () => {
		try {
			const key = await deriveKeyFromPassword(password, salt);
			const encoded = await base32EncodeKey(key);
			strictEqual(encoded, expected, 'Password derived keys should encode to expected value.');
		} catch(err) {
			controller.abort(err);
		}
	});
});
