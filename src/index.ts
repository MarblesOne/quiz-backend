import { z } from 'zod';
import { SignJWT, importPKCS8 } from 'jose';

// This defines the structure of your Environment Variables
export interface Env {
	GOOGLE_CLIENT_EMAIL: string;
	GOOGLE_PRIVATE_KEY: string;
	GOOGLE_SHEET_ID: string;
	ALLOWED_ORIGIN: string;
}

// 1. Zod Schema for strict payload validation
const quizPayloadSchema = z.object({
	name: z.string().min(1, "Name is required"),
	mobile: z.string().min(10, "Mobile must be at least 10 characters"),
	email: z.string().email("Invalid email address"),
	final_score: z.number(),
	answers: z.array(z.union([z.string(), z.number()])),
});

// 2. Helper function to prevent Google Sheets Formula Injection
function sanitizeInput(value: string | number): string | number {
	if (typeof value === 'string') {
		// If the string starts with a formula character, prepend a single quote
		if (/^[=+\-@]/.test(value)) {
			return `'${value}`;
		}
	}
	return value;
}

// Rate Limiter Setup (Isolate-level)
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 5;
const ipRequestMap = new Map<string, number[]>();

async function getGoogleAuthToken(env: Env): Promise<string> {
    // Trim the key to remove any accidental leading/trailing whitespace,
    // then replace literal \n sequences with real newlines
    const formattedKey = env.GOOGLE_PRIVATE_KEY.trim().replace(/\\n/g, '\n');




    const privateKey = await importPKCS8(formattedKey, 'RS256');
    const now = Math.floor(Date.now() / 1000);

    // Use ONLY the builder methods for standard claims (iss, aud, exp, iat)
    // Pass custom claims (scope) in the constructor payload
    const jwt = await new SignJWT({
        scope: 'https://www.googleapis.com/auth/spreadsheets',
    })
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuer(env.GOOGLE_CLIENT_EMAIL)
        .setAudience('https://oauth2.googleapis.com/token')
        .setIssuedAt(now)
        .setExpirationTime(now + 3600)
        .sign(privateKey);

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: jwt,
        }),
    });

    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to get Google Auth token: ${error}`);
    }

    const data = (await response.json()) as { access_token: string };
    return data.access_token;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// Strict Environment Variable Validation
		if (!env.GOOGLE_CLIENT_EMAIL || !env.GOOGLE_PRIVATE_KEY || !env.GOOGLE_SHEET_ID || !env.ALLOWED_ORIGIN) {
			return new Response(JSON.stringify({ error: 'Internal Server Error (Configuration)' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		}

		// 3. Lockdown CORS using environment variable
		const corsHeaders = {
			'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
		};

		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders, status: 204 });
		}

		// Rate Limiting Logic
		const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
		if (clientIP !== 'unknown') {
			const now = Date.now();
			const requests = ipRequestMap.get(clientIP) || [];
			
			// Clean up old timestamps
			const recentRequests = requests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW_MS);
			
			if (recentRequests.length >= MAX_REQUESTS_PER_WINDOW) {
				return new Response(JSON.stringify({ error: 'Too Many Requests' }), {
					status: 429,
					headers: { ...corsHeaders, 'Content-Type': 'application/json' },
				});
			}
			
			recentRequests.push(now);
			ipRequestMap.set(clientIP, recentRequests);
		}

		try {
			// Parse the request body as unknown before validation
			const rawData: unknown = await request.json();

			// 1. Parse and validate the payload using Zod
			const validationResult = quizPayloadSchema.safeParse(rawData);

			if (!validationResult.success) {
				return new Response(
					JSON.stringify({
						error: 'Validation failed',
						details: validationResult.error.format(),
					}),
					{
						status: 400,
						headers: { ...corsHeaders, 'Content-Type': 'application/json' },
					}
				);
			}

			const data = validationResult.data;
			const token = await getGoogleAuthToken(env);

			// Transform data for Sheets API (flat array)
			const values = [
				new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
				sanitizeInput(data.name),
				sanitizeInput(data.mobile),
				sanitizeInput(data.email),
				data.final_score,
				...data.answers.map(sanitizeInput),
			];

			const sheetsResponse = await fetch(
				`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!A1:append?valueInputOption=USER_ENTERED`,
				{
					method: 'POST',
					headers: {
						Authorization: `Bearer ${token}`,
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({ values: [values] }),
				}
			);

			if (!sheetsResponse.ok) {
				const error = await sheetsResponse.text();
				throw new Error(`Google Sheets API error: ${error}`);
			}

			return new Response(JSON.stringify({ status: 'success' }), {
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		} catch (e) {
			console.error('Internal server error:', e);
			return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
				status: 500,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}
	},
};