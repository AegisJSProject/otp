import { createOTPAuthURI, verifyTOTP, deriveKeyFromPassword, keyToSecret } from '@aegisjsproject/otp';
import { createSVGBlob } from '@aegisjsproject/qr-encoder';
import { $state, $attr, $watch, $text, $disabled, $peek, $render, $html } from '@aegisjsproject/iota';
import { onSubmit, onClick, onReset, signal as sig, observeEvents } from '@aegisjsproject/callback-registry';
import properties from '@aegisjsproject/styles/css/properties.css' with { type: 'css' };
import theme from '@aegisjsproject/styles/css/theme.css' with { type: 'css' };
import forms from '@aegisjsproject/styles/css/forms.css' with { type: 'css' };
import button from '@aegisjsproject/styles/css/button.css' with { type: 'css' };
import scrollbar from '@aegisjsproject/styles/css/scrollbar.css' with { type: 'css' };
import misc from '@aegisjsproject/styles/css/misc.css' with { type: 'css' };
import pkg from '@aegisjsproject/otp/package.json' with { type: 'json' };

// Missing because ESLint is using node globals, not browser
/* global document, location, reportError */
const stack = new DisposableStack();
const { signal } = stack.adopt(new AbortController(), controller => controller.abort(new DOMException('Stack disposed', 'AbortError')));
const $key = stack.use($state(null));
const $uri = stack.use($attr('src', location.href));
const $error = stack.use($text(null));
const $verifiyMessage = stack.use($text('No TOPT code entered yet.'));
const $disposed = $disabled(signal.aborted);
const $disabledOnMissingKey = stack.use($disabled(() => $disposed.get() || ! ($key.get() instanceof CryptoKey)));

const salt = new Uint8Array([
	215, 160, 144, 104, 164,
	250, 128, 205,  35,  14,
	58,  17, 240,  87, 125,
	89
]); // Just some randomly generated but fixed salt

document.title = pkg.name;
document.adoptedStyleSheets = [properties, theme, forms, button, scrollbar, misc];
const desc = document.createElement('meta');
const keywords = document.createElement('meta');
desc.name = 'description';
desc.content = pkg.description;
keywords.name = 'keywords';
keywords.content = pkg.keywords.join(', ');
document.head.append(desc, keywords);

$watch($key, key => {
	if (key instanceof CryptoKey) {
		keyToSecret(key).then(secret => {
			const otpUri = createOTPAuthURI({
				label: 'A TOTP Test',
				issuer: location.hostname,
				secret: secret,
			});

			const blob = createSVGBlob(otpUri);
			Promise.try(URL.revokeObjectURL, $peek($uri));
			$uri.set(URL.createObjectURL(blob));
		}).catch(err => {
			reportError(err);

			if (err instanceof Error) {
				$error.set(err.message);
			} else {
				$error.set(err);
			}
		});
	}
});

$watch($error, err => {
	if (typeof err === 'string' && err.length !== 0) {
		document.getElementById('totp-error').showPopover();
	}
});

// Does not handle tagged template indentation correctly
/* eslint indent: off */
$render($html`
	<dialog id="totp-generate-modal">
		<form method="dialog" id="totp-generate-form" ${onSubmit}="${async event => {
			event.preventDefault();
			const { target, submitter } = event;
			submitter.disabled = true;

			try {
				const data = new FormData(target);
				const key = await deriveKeyFromPassword(data.get('password'), salt);
				$key.set(key);
			} catch(err) {
				reportError(err);

				if (err instanceof Error) {
					$error.set(err.message);
				} else {
					$error.set(err);
				}
			} finally {
				submitter.disabled = false;
			}
		}}"
		${onReset}="${() => $key.set(null)}"
		${sig}="${signal}">
			<div class="form-group">
				<label for="totp-generate-password" class="input-label required">Secret Password</label>
				<input type="password" name="password" id="totp-generate-password" class="input" placeholder="********" minlength="8" autocomplete="off" required="" />
			</div>
			<div class="flex row">
				<button type="submit" class="btn btn-success">Submit</button>
				<button type="reset" class="btn btn-warning">Reset</button>
				<button type="button" class="btn btn-danger" command="close" commandfor="totp-generate-modal">Dismiss</button>
			</div>
		</form>
	</dialog>
	<dialog id="totp-verify-modal">
		<form method="dialog" id="totp-verify-form" ${onSubmit}="${async event => {
			event.preventDefault();
			const { submitter, target } = event;
			submitter.disabled = true;

			try {
				const data = new FormData(target);
				const valid = await verifyTOTP(data.get('totp'), $key.get());
				$verifiyMessage.set(valid ? 'TOTP Code is valid' : 'TOTP Code is not valid.');
			} catch(err) {
				reportError(err);

				if (err instanceof Error) {
					$error.set(err.message);
				} else {
					$error.set(err);
				}
			} finally {
				submitter.disabled = false;
			}
		}}"
		${sig}="${signal}">
			<div class="form-group">
				<label for="totp-verify-code" class="input-label required">TOTP Code</label>
				<input type="password" name="totp" id="totp-verify-code" class="input" placeholder="######" minlength="6" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" autocomplete="off" ${$disabledOnMissingKey} required="" />
			</div>
			<p>${$verifiyMessage}</p>
			<div class="flex row">
				<button type="submit" class="btn btn-success" ${$disabledOnMissingKey}>Submit</button>
				<button type="reset" class="btn btn-warning" ${$disabledOnMissingKey}>Reset</button>
				<button type="button" class="btn btn-danger" command="close" commandfor="totp-verify-modal">Dismiss</button>
			</div>
		</form>
	</dialog>
	<dialog id="totp-scan-modal">
		<img ${$uri} alt="OTP Auth URI QR" loading="lazy" />
		<button type="button" class="btn btn-danger" command="close" commandfor="totp-scan-modal">Dismiss</button>
	</dialog>
	<div id="totp-error" popover="auto">
		<pre class="status-box error">${$error}</pre>
		<button type="button" class="btn btn-danger" command="hide-popover" commandfor="totp-error">Dismiss</button>
	</div>
	<button type="button" class="btn btn-primary" command="show-modal" commandfor="totp-generate-modal" ${$disposed}>Generate</button>
	<button type="button" class="btn btn-primary" command="show-modal" commandfor="totp-verify-modal" ${$disabledOnMissingKey}>Verify</button>
	<button type="button" class="btn btn-primary" command="show-modal" commandfor="totp-scan-modal" ${$disabledOnMissingKey}>Scan</button>
	<button type="button" class="btn btn-danger" ${onClick}="${() => {
		// Set first so updates occur
		$disposed.set(true);
		stack.dispose();
	}}" ${sig}="${signal}" ${$disposed}>Dispose</button>
`, document.body);

observeEvents();
