/**
 * GitHub OAuth token-exchange proxy for Patchwork Forums.
 */

function parseAllowedOrigins(csv) {
	return (csv ?? '')
		.split(',')
		.map((origin) => origin.trim().replace(/\/+$/, ''))
		.filter(Boolean);
}

export default {
	async fetch(request, env) {
		const allowed = parseAllowedOrigins(env.ALLOWED_ORIGINS);
		const origin = request.headers.get('Origin');
		const originAllowed =
			origin !== null && allowed.includes(origin);

		const cors = {
			...(originAllowed
				? { 'Access-Control-Allow-Origin': origin }
				: {}),
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
			Vary: 'Origin'
		};

		const json = (body, status = 200) =>
			new Response(JSON.stringify(body), {
				status,
				headers: {
					'Content-Type': 'application/json',
					...cors
				}
			});

		// Handle browser CORS preflight.
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: cors
			});
		}

		// Only POST is supported.
		if (request.method !== 'POST') {
			return json(
				{ error: 'method_not_allowed' },
				405
			);
		}

		// Only allow requests from the forum.
		if (!originAllowed) {
			return json(
				{ error: 'forbidden_origin' },
				403
			);
		}

		let body;

		try {
			body = await request.json();
		} catch {
			return json(
				{ error: 'invalid_json' },
				400
			);
		}

		const code = body?.code;

		if (!code || typeof code !== 'string') {
			return json(
				{ error: 'missing_code' },
				400
			);
		}

		// Exchange the temporary GitHub OAuth code for an access token.
		const githubResponse = await fetch(
			'https://github.com/login/oauth/access_token',
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json'
				},
				body: JSON.stringify({
					client_id: env.GITHUB_CLIENT_ID,
					client_secret: env.GITHUB_CLIENT_SECRET,
					code,
					redirect_uri:
						'https://patch-com.github.io/auth/callback'
				})
			}
		);

		let githubData;

		try {
			githubData = await githubResponse.json();
		} catch {
			return json(
				{ error: 'invalid_github_response' },
				502
			);
		}

		// GitHub rejected the OAuth exchange.
		if (!githubResponse.ok || !githubData.access_token) {
			return json(
				{
					error:
						githubData.error ??
						'exchange_failed',
					error_description:
						githubData.error_description ??
						undefined
				},
				400
			);
		}

		// Only return the access token to the forum.
		return json({
			access_token: githubData.access_token
		});
	}
};
