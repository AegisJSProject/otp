import terser from '@rollup/plugin-terser';

export default [{
	input: 'otp.js',
	output: [{
		file: 'otp.cjs',
		format: 'cjs',
	}, {
		file: 'otp.min.js',
		format: 'esm',
		plugins: [terser()],
		sourcemap: true,
	}],
}, {
	input: 'consts.js',
	output: {
		file: 'consts.cjs',
		format: 'cjs',
	}
}];
