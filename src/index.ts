import { GoogleSpreadsheet } from 'google-spreadsheet';
import { JWT } from 'google-auth-library';

// This defines the structure of your Environment Variables
export interface Env {
	GOOGLE_CLIENT_EMAIL: string;
	GOOGLE_PRIVATE_KEY: string;
	GOOGLE_SHEET_ID: string;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type',
		};

		if (request.method === 'OPTIONS') {
			return new Response(null, { headers: corsHeaders });
		}

		try {
			const data: any = await request.json();

			const auth = new JWT({
				email: env.GOOGLE_CLIENT_EMAIL,
				key: env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
				scopes: ['https://www.googleapis.com/auth/spreadsheets'],
			});

			const doc = new GoogleSpreadsheet(env.GOOGLE_SHEET_ID, auth);
			await doc.loadInfo();
			const sheet = doc.sheetsByIndex[0];

			const rowData: any = {
				Timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
				Name: data.name,
				Mobile: data.mobile,
				Email: data.email,
				'Final Score': data.final_score,
			};

			// Map answers Q1, Q2, etc.
			data.answers.forEach((val: any, i: number) => {
				rowData[`Q${i + 1}`] = val;
			});

			await sheet.addRow(rowData);

			return new Response(JSON.stringify({ status: 'success' }), {
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		} catch (e: any) {
			return new Response(JSON.stringify({ error: e.message }), {
				status: 500,
				headers: corsHeaders,
			});
		}
	},
};