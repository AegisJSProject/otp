import home from '@aegisjsproject/dev-server';
import favicon from '@aegisjsproject/dev-server/favicon';
import { Importmap, imports, scopes } from '@shgysk8zer0/importmap';

const importmap = new Importmap({ imports, scopes });
await importmap.importLocalPackage();
const integrity = await importmap.getIntegrity();

const csp = `default-src 'none'; script-src ${imports['@shgysk8zer0/polyfills']} '${integrity}'; style-src 'self'; img-src 'self'; require-trusted-types-for 'script';`;

export default {
	open: true,
	routes: {
		'/': home,
		'/favicon.svg': favicon,
	},
	responsePostprocessors: [
		(response, { request }) => {
			if (request.destination === 'document') {
				response.headers.set('Content-Type', 'text/html');
				response.headers.set('Content-Security-Policy', csp);
			}
		}
	],
};
