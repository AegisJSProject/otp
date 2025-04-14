import { describe, test } from 'node:test';
import { ok, deepStrictEqual, strictEqual } from 'node:assert';
import { createOTPAuthURI, parseOTPAuthURI, generateTOTP, generateSecret, verifyTOTP, secretToKey } from '@aegisjsproject/otp';

const controller = new AbortController();
const signal = AbortSignal.any([AbortSignal.timeout(1000), controller.signal]);

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
});
