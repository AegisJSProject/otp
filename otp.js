import {
	DEFAULT_ALGO, DEFAULT_DIGITS, DEFAULT_PERIOD, DEFAULT_SECRET_LENGTH, DEFAULT_ALLOWED_SKEW,
	TOTP, BASE32_ALPHABET, SUPPORTED_TYPES, SHA1,
} from './consts.js';

/**
 * Generates a cryptographically secure random secret.
 *
 * @param {number} [length=20] The desired length of the secret in bytes.
 * @returns {Uint8Array} A Uint8Array containing the random bytes.
 */
export const generateSecret = (length = DEFAULT_SECRET_LENGTH) => crypto.getRandomValues(new Uint8Array(length));

/**
 * Derives a cryptographic key from a password using the PBKDF2 algorithm.
 *
 * @param {string} password The password to derive the key from.
 * @param {Uint8Array} salt A cryptographically random salt. Should be unique per password.
 * @param {object} [options={}] Optional parameters for the key derivation.
 * @param {number} [options.iterations=100_000] The number of iterations for PBKDF2. Higher numbers increase security but also computation time.
 * @param {number} [options.length=160] The desired length of the derived key in bits. Defaults to 160, suitable for HMAC-SHA1.
 * @param {HashAlgorithmIdentifier} [options.hash="SHA-1"] The hash algorithm to use within PBKDF2 and for the derived HMAC key. Standard string identifiers like "SHA-1", "SHA-256", etc.
 * @param {boolean} [options.extractable=true] Whether the derived key can be exported.
 * @returns {Promise<CryptoKey>} A promise that resolves with the derived CryptoKey.
 */
export async function deriveKeyFromPassword(password, salt, {
	iterations = 100_000,
	length = 160,
	hash = SHA1,
	extractable = true,
} = {}) {
	const baseKey = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(password),
		{ name: 'PBKDF2' },
		false,
		['deriveKey']
	);

	return await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt,
			iterations,
			hash,
		},
		baseKey,
		{
			name: 'HMAC',
			hash,
			length,
		},
		extractable,
		['sign']
	);
}

/**
 * Encodes a Uint8Array secret into a Base32 string (RFC 4648).
 *
 * @param {Uint8Array|ArrayBuffer} bytes The secret bytes to encode.
 * @returns {string} The Base32 encoded representation of the secret.
 */
export function base32Encode(bytes) {
	if (bytes instanceof ArrayBuffer) {
		return base32Encode(new Uint8Array(bytes));
	} else if (bytes instanceof Uint8Array) {
		let bits = '';
		let output = '';

		for (const byte of bytes) {
			bits += byte.toString(2).padStart(8, '0');

			while (bits.length >= 5) {
				output += BASE32_ALPHABET[parseInt(bits.slice(0, 5), 2)];
				bits = bits.slice(5);
			}
		}

		if (bits.length > 0) {
			output += BASE32_ALPHABET[parseInt(bits.padEnd(5, '0'), 2)];
		}

		return output;
	} else {
		throw new TypeError('Bytes must be an `ArrayBuffer` or `Uint8Array`.');
	}
}

/**
 * Exports a CryptoKey to its raw byte format and then encodes it as a Base32 string.
 *
 * @param {CryptoKey} key The CryptoKey to export and encode. The key must be extractable.
 * @returns {Promise<string>} A promise that resolves with the Base32 encoded representation of the key's raw data.
 * @throws {Error} If the key is not extractable or another export error occurs.
 */
export const base32EncodeKey = async key => base32Encode(await crypto.subtle.exportKey('raw', key));

/**
 * Decodes a Base32 encoded string (RFC 4648) back into a Uint8Array.
 * Invalid characters in the input string are ignored.
 *
 * @param {string} base32Str The Base32 encoded string to decode.
 * @returns {Uint8Array} A Uint8Array containing the decoded bytes.
 * @throws {Error} If the input string contains invalid Base32 characters.
 */
export function base32Decode(base32Str) {
	let bits = '';
	const bytes = [];
	// Normalize input: uppercase and remove any non-alphabet characters (like padding '=')
	const normalizedStr = base32Str.toUpperCase().replace(/[^A-Z2-7]/g, '');

	for (let i = 0; i < normalizedStr.length; i++) {
		const char = normalizedStr[i];
		const value = BASE32_ALPHABET.indexOf(char);

		if (value === -1) {
			// This shouldn't happen with the regex replace, but good practice
			throw new Error(`Invalid Base32 character found: ${char}`);
		}

		bits += value.toString(2).padStart(5, '0');

		// Extract 8-bit chunks (bytes)
		while (bits.length >= 8) {
			const byteStr = bits.slice(0, 8);
			bytes.push(parseInt(byteStr, 2));
			bits = bits.slice(8);
		}
	}

	// Any remaining bits are discarded as they cannot form a full byte.
	// This is consistent with how Base32 padding works (or lack thereof in otpauth).

	return new Uint8Array(bytes);
}

/**
 * Converts a raw secret Uint8Array into a CryptoKey for HMAC operations using the Web Crypto API.
 *
 * @param {Uint8Array} secret The raw secret bytes.
 * @param {object} [options={}] Configuration options for key import.
 * @param {AlgorithmIdentifier} [options.algorithm="SHA-1"] The HMAC hashing algorithm to use (e.g., "SHA-1", "SHA-256", "SHA-512").
 * @param {boolean} [options.extractable=true] Whether the key can be exported using `crypto.subtle.exportKey`.
 * @param {KeyUsage[]} [options.usages=["sign"]] The allowed usages for the key (e.g., "sign", "verify").
 * @returns {Promise<CryptoKey>} A Promise resolving to the imported CryptoKey object.
 */
export async function secretToKey(secret, {
	algorithm = DEFAULT_ALGO,
	extractable = true,
	usages = ['sign'],
} = {}) {
	return await crypto.subtle.importKey(
		'raw',
		secret,
		{ name: 'HMAC', hash: { name: algorithm }},
		extractable,
		usages,
	);
}

/**
 * Creates an `otpauth://totp/` URI for easy provisioning of TOTP secrets in authenticator apps.
 *
 * @param {object} config Configuration options for the URI.
 * @param {string} config.label The label identifying the account (e.g., "user@example.com" or "Example Inc:user"). It will be URL encoded.
 * @param {string} config.issuer The name of the service or organization issuing the OTP (e.g., "Example Inc").
 * @param {Uint8Array} config.secret The raw secret bytes. It will be Base32 encoded.
 * @param {string} [config.algorithm="SHA-1"] The hashing algorithm used (e.g., "SHA1", "SHA256", "SHA512"). Note: Hyphen is removed for the URI.
 * @param {number} [config.digits=6] The number of digits in the OTP code (typically 6 or 8).
 * @param {number} [config.period=30] The time period in seconds for OTP generation (typically 30 or 60).
 * @returns {string} The otpauth URI string.
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function createOTPAuthURI({
	label,
	issuer,
	secret,
	algorithm = DEFAULT_ALGO,
	digits = DEFAULT_DIGITS,
	period = DEFAULT_PERIOD,
}) {
	const params = new URLSearchParams({
		secret: base32Encode(secret),
		issuer,
		algorithm: algorithm.replaceAll('-', ''),
		digits,
		period
	});

	return `otpauth://${TOTP}/${encodeURIComponent(label)}?${params.toString()}`;
}

/**
 * Parses an otpauth:// URI and extracts its components.
 *
 * @param {string} uri The otpauth URI to parse
 * @returns {{
 *	 type: 'totp'|'hotp',
 *	 label: string,
 *	 issuer: string,
 *	 secret: Uint8Array,
 *	 algorithm: string,
 *	 digits: number,
 *	 period?: number,
 *	 counter?: number
 * }} An object containing the parsed components
 * @throws {TypeError} If the URI is invalid or missing required components
 */
export function parseOTPAuthURI(uri) {
	const url = new URL(uri);
	const params = url.searchParams;
	const type = url.host;
	const encodedLabel = url.pathname.substring(1);

	if (url.protocol !== 'otpauth:') {
		throw new TypeError('Invalid OTP URI format: must start with "otpauth://"');
	} else if (! SUPPORTED_TYPES.includes(type)) {
		throw new Error(`Unsupported OTP type: ${type}`);
	} else if (typeof encodedLabel !== 'string' || encodedLabel.length === 0) {
		throw new TypeError('Missing account label in OTP URI');
	} else if (! params.has('secret')) {
		throw new TypeError('Missing required "secret" parameter in OTP URI');
	} else {
		const label = decodeURIComponent(encodedLabel);
		const secret = base32Decode(params.get('secret'));

		// Extract issuer (can be in params or as part of the label)
		const issuer = params.has('issuer') ? params.get('issuer') : label.split(':')[0];

		let algorithm = params.has('algorithm') ? params.get('algorithm').toUpperCase() : 'SHA-1';

		if (! algorithm.includes('-')) {
			// Convert 'SHA1' to 'SHA-1' format
			algorithm = algorithm.replace(/^(SHA)(\d+)$/, '$1-$2');
		}

		const digits = params.has('digits') ? parseInt(params.get('digits')) : DEFAULT_DIGITS;

		const result = {
			type,
			label,
			issuer,
			secret,
			algorithm,
			digits
		};

		// Add type-specific properties
		if (type === 'totp') {
			result.period = params.has('period') ? parseInt(params.get('period')) : DEFAULT_PERIOD;
		} else if (type === 'hotp') {
			const counter = params.get('counter');

			if (counter === null) {
				throw new TypeError('Missing required "counter" parameter for HOTP URI');
			}

			result.counter = parseInt(counter);
		}

		return result;
	}
}

/**
 * Generates a Time-based One-Time Password (TOTP) using the provided CryptoKey and options.
 * Implements RFC 6238.
 *
 * @param {CryptoKey} secretKey The CryptoKey derived from the shared secret using `secretToKey`. Must have "sign" usage.
 * @param {object} [options={}] Configuration options for TOTP generation.
 * @param {number} [options.digits=6] The number of digits for the OTP code (e.g., 6 or 8).
 * @param {number} [options.period=30] The time step in seconds (e.g., 30 or 60).
 * @param {number} [options.time=Date.now()] The timestamp in milliseconds since epoch to use for calculation (defaults to current time).
 * @returns {Promise<string>} A Promise resolving to the generated TOTP code as a string, padded with leading zeros if necessary.
 */
export async function generateTOTP(secretKey, {
	digits = DEFAULT_DIGITS,
	period = DEFAULT_PERIOD,
	time = Date.now(),
} = {}) {
	const counter = Math.floor(time / 1000 / period);
	const buf = new ArrayBuffer(8);
	const view = new DataView(buf);
	view.setUint32(4, counter, false); // Big-endian 64-bit int, high bits zero

	const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', secretKey, buf));
	const offset = hmac[hmac.length - 1] & 0x0f;
	const code = (
		((hmac[offset] & 0x7f) << 24) |
		(hmac[offset + 1] << 16) |
		(hmac[offset + 2] << 8) |
		(hmac[offset + 3])
	) % (10 ** digits);

	return code.toString().padStart(digits, '0');
}

/**
 * Verifies a given Time-based One-Time Password (TOTP) code against the expected code,
 * allowing for a specified time skew (checking previous/future time steps).
 *
 * @param {string} input The TOTP code entered by the user (e.g., "123456").
 * @param {CryptoKey} secretKey The CryptoKey derived from the shared secret using `secretToKey`. Must have "sign" usage.
 * @param {object} [options={}] Configuration options for TOTP verification.
 * @param {number} [options.digits=6] The number of digits in the OTP code. Must match the digits used for generation.
 * @param {number} [options.period=30] The time period in seconds. Must match the period used for generation.
 * @param {number} [options.allowedSkew=1] The number of time steps (periods) before or after the current time step to check. `0` checks only the current step, `1` checks current, previous, and next steps (total 3).
 * @param {number} [options.time=Date.now()] The timestamp in milliseconds since epoch to use for verification (defaults to current time).
 * @returns {Promise<boolean>} A Promise resolving to `true` if the input code is valid within the allowed time skew, `false` otherwise.
 */
export async function verifyTOTP(input, secretKey, {
	digits = DEFAULT_DIGITS,
	period = DEFAULT_PERIOD,
	allowedSkew = DEFAULT_ALLOWED_SKEW,
	time = Date.now(),
} = {}) {
	const t = Math.floor(time / 1000 / period);
	let match = false;

	for (let offset = -allowedSkew; offset <= allowedSkew; ++offset) {
		const code = await generateTOTP(secretKey, {
			period,
			digits,
			time: (t + offset) * period * 1000
		});

		if (input === code) {
			match = true;
			break;
		};
	}

	return match;
}
