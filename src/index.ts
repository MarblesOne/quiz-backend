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

const schedulePayloadSchema = z.object({
	name: z.string().min(1, "Name is required"),
	mobile: z.string().min(10, "Mobile must be at least 10 characters"),
	email: z.string().email("Invalid email address"),
});

// 2. Helper function to prevent Google Sheets Formula Injection
function sanitizeInput(value: string | number): string | number {
	if (typeof value === 'string') {
		if (/^[=+\-@]/.test(value)) {
			return `'${value}`;
		}
	}
	return value;
}

// Rate Limiter Setup (Isolate-level)
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;
const ipRequestMap = new Map<string, number[]>();

// Column indices (0-based)
// A=0, B=1, C=2, D=3, E–Q=4–16, R=17, S=18(human/untouched), T=19
const COL_NAME   = 1;
const COL_MOBILE = 2;
const COL_EMAIL  = 3;
const COL_R      = 17; // System: call requested timestamp
// COL_S = 18        — Human notes, Worker never touches this
const COL_T      = 19; // System: request count

async function getGoogleAuthToken(env: Env): Promise<string> {
	const formattedKey = env.GOOGLE_PRIVATE_KEY.trim().replace(/\\n/g, '\n');
	const privateKey = await importPKCS8(formattedKey, 'RS256');
	const now = Math.floor(Date.now() / 1000);

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

		// Lockdown CORS using environment variable
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

		// ── Routing ──────────────────────────────────────────────
		const url = new URL(request.url);

		if (url.pathname === '/submit') {
			return handleSubmit(request, env, corsHeaders);
		}

		if (url.pathname === '/schedule') {
			return handleSchedule(request, env, corsHeaders);
		}

		return new Response(JSON.stringify({ error: 'Not Found' }), {
			status: 404,
			headers: { ...corsHeaders, 'Content-Type': 'application/json' },
		});
	},
};

// ── Route Handlers ────────────────────────────────────────────

async function handleSubmit(
	request: Request,
	env: Env,
	corsHeaders: Record<string, string>
): Promise<Response> {
	try {
		const rawData: unknown = await request.json();

		const validationResult = quizPayloadSchema.safeParse(rawData);
		if (!validationResult.success) {
			return new Response(
				JSON.stringify({ error: 'Validation failed', details: validationResult.error.format() }),
				{ status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
			);
		}

		const data = validationResult.data;
		const token = await getGoogleAuthToken(env);

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
}

async function handleSchedule(
	request: Request,
	env: Env,
	corsHeaders: Record<string, string>
): Promise<Response> {
	try {
		const rawData: unknown = await request.json();

		const validationResult = schedulePayloadSchema.safeParse(rawData);
		if (!validationResult.success) {
			return new Response(
				JSON.stringify({ error: 'Validation failed', details: validationResult.error.format() }),
				{ status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
			);
		}

		const { name, mobile, email } = validationResult.data;
		const token = await getGoogleAuthToken(env);

		// Step 1: Fetch all rows (columns B, C, D only) to find the matching row
		const getResponse = await fetch(
			`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!B:D`,
			{
				headers: { Authorization: `Bearer ${token}` },
			}
		);

		if (!getResponse.ok) {
			const error = await getResponse.text();
			throw new Error(`Google Sheets read error: ${error}`);
		}

		const getResult = (await getResponse.json()) as { values?: string[][] };
		const rows = getResult.values || [];

		// Step 2: Find matching row index (1-based for Sheets, rows[0] = row 1)
		

		// Note: We fetched B:D so within that range indices are 0, 1, 2
		// COL_NAME-1 = 0 (B), COL_MOBILE-2 = 0... let me be explicit:
		const rowMatchIndex = rows.findIndex(
			row =>
				row[0]?.trim() === name.trim()   &&  // B
				row[1]?.trim() === mobile.trim() &&  // C
				row[2]?.trim() === email.trim()      // D
		);

		if (rowMatchIndex === -1) {
			return new Response(JSON.stringify({ error: 'User not found' }), {
				status: 404,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}

		// rowMatchIndex is 0-based in our array. Row 1 in Sheets = index 0.
		// So the actual Sheets row number is rowMatchIndex + 1
		const sheetRowNumber = rowMatchIndex + 1;

		// Step 3: Read current value of Column T (request count) for this row
		const tCell = `Sheet1!T${sheetRowNumber}`;
		const tResponse = await fetch(
			`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${tCell}`,
			{
				headers: { Authorization: `Bearer ${token}` },
			}
		);

		if (!tResponse.ok) {
			const error = await tResponse.text();
			throw new Error(`Google Sheets read error (col T): ${error}`);
		}

		const tResult = (await tResponse.json()) as { values?: string[][] };
		const existingCount = parseInt(tResult.values?.[0]?.[0] || '0', 10);
		const newCount = isNaN(existingCount) ? 1 : existingCount + 1;

		// Step 4: Write timestamp to Col R and updated count to Col T
		// Col S (human notes) is intentionally never touched
		const timestamp = 'Call Requested';

		const updateResponse = await fetch(
			`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/Sheet1!R${sheetRowNumber}:T${sheetRowNumber}?valueInputOption=USER_ENTERED`,
			{
				method: 'PUT',
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json',
				},
				// R = timestamp, S = untouched (empty string keeps it safe), T = count
				body: JSON.stringify({ values: [[timestamp, null, newCount]] }),
			}
		);

		if (!updateResponse.ok) {
			const error = await updateResponse.text();
			throw new Error(`Google Sheets write error: ${error}`);
		}

		return new Response(JSON.stringify({ status: 'success', requestCount: newCount }), {
			headers: { ...corsHeaders, 'Content-Type': 'application/json' },
		});

	} catch (e) {
		console.error('Internal server error:', e);
		return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
			status: 500,
			headers: { ...corsHeaders, 'Content-Type': 'application/json' },
		});
	}
}