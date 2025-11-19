/**
 * Complete Next.js + Vercel Example
 * This file shows snippets for different parts of your Next.js app
 * Copy the relevant sections to your actual files
 */

/* ===========================================
   1. next.config.js
   =========================================== */

// const nextConfig = {
//   experimental: {
//     serverComponentsExternalPackages: ['aimless-security']
//   }
// }
// module.exports = nextConfig

/* ===========================================
   2. lib/security.ts - Shared Security Helper
   =========================================== */

// import { Aimless } from 'aimless-security';
// 
// const aimless = new Aimless({
//   rasp: {
//     enabled: true,
//     blockMode: false,
//     trustedOrigins: [process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000']
//   }
// });
// 
// export function validateUserInput(input: string, types: ('sql' | 'xss' | 'command' | 'path')[] = ['sql', 'xss']) {
//   try {
//     return aimless.validate(input).against(types).sanitize().result();
//   } catch (error) {
//     return { safe: true, sanitized: input, threats: [] };
//   }
// }
// 
// export function checkIPReputation(ip: string): number {
//   try {
//     return aimless.getIPReputation(ip);
//   } catch {
//     return 100;
//   }
// }
// 
// export { aimless };

/* ===========================================
   3. app/api/contact/route.ts - Protected API Route
   =========================================== */

// export const runtime = 'nodejs'; // CRITICAL for Vercel!
// 
// import { NextRequest, NextResponse } from 'next/server';
// import { validateUserInput } from '@/lib/security';
// 
// export async function POST(request: NextRequest) {
//   try {
//     const body = await request.json();
//     const { name, email, message } = body;
//     
//     const messageValidation = validateUserInput(message, ['xss', 'sql']);
//     
//     if (!messageValidation.safe) {
//       return NextResponse.json({
//         error: 'Invalid input detected',
//         details: messageValidation.threats
//       }, { status: 400 });
//     }
//     
//     await saveToDatabase({
//       name,
//       email,
//       message: messageValidation.sanitized
//     });
//     
//     return NextResponse.json({ success: true });
//   } catch (error) {
//     return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
//   }
// }

/* ===========================================
   4. app/api/search/route.ts - Search with Validation
   =========================================== */

// export const runtime = 'nodejs';
// 
// import { NextRequest, NextResponse } from 'next/server';
// import { validateUserInput } from '@/lib/security';
// 
// export async function GET(request: NextRequest) {
//   const query = request.nextUrl.searchParams.get('q') || '';
//   const validation = validateUserInput(query, ['sql', 'xss']);
//   
//   if (!validation.safe) {
//     return NextResponse.json({ error: 'Invalid query' }, { status: 400 });
//   }
//   
//   const results = await searchDatabase(validation.sanitized);
//   return NextResponse.json({ results });
// }

/* ===========================================
   5. app/api/admin/route.ts - IP Reputation Check
   =========================================== */

// export const runtime = 'nodejs';
// 
// import { NextRequest, NextResponse } from 'next/server';
// import { checkIPReputation } from '@/lib/security';
// 
// export async function GET(request: NextRequest) {
//   const ip = request.ip || request.headers.get('x-forwarded-for') || 'unknown';
//   const reputation = checkIPReputation(ip);
//   
//   if (reputation < 50) {
//     return NextResponse.json({
//       error: 'Access denied - IP flagged'
//     }, { status: 403 });
//   }
//   
//   return NextResponse.json({ message: 'Access granted' });
// }

/* ===========================================
   6. Server Action Example - app/actions.ts
   =========================================== */

// 'use server';
// 
// import { validateUserInput } from '@/lib/security';
// 
// export async function submitReview(formData: FormData) {
//   const review = formData.get('review') as string;
//   const validation = validateUserInput(review, ['xss', 'sql']);
//   
//   if (!validation.safe) {
//     return { success: false, error: 'Invalid content' };
//   }
//   
//   await saveReview({ review: validation.sanitized });
//   return { success: true };
// }

/* ===========================================
   7. Middleware - middleware.ts (Optional)
   =========================================== */

// import { NextResponse } from 'next/server';
// import type { NextRequest } from 'next/server';
// 
// export function middleware(request: NextRequest) {
//   const response = NextResponse.next();
//   response.headers.set('X-Content-Type-Options', 'nosniff');
//   response.headers.set('X-Frame-Options', 'DENY');
//   response.headers.set('X-XSS-Protection', '1; mode=block');
//   return response;
// }

/* ===========================================
   8. Environment Variables - .env.local
   =========================================== */

// NEXT_PUBLIC_APP_URL=https://yourdomain.com
// NODE_ENV=production

/* ===========================================
   9. Deployment Checklist
   =========================================== */

// ✅ Add `export const runtime = 'nodejs';` to all API routes using Aimless
// ✅ Add `serverComponentsExternalPackages: ['aimless-security']` to next.config.js
// ✅ Set `blockMode: false` for initial deployment
// ✅ Wrap all Aimless calls in try-catch
// ✅ Only validate POST/PUT routes with user input
// ✅ Test locally with `npm run build && npm start`
// ✅ Deploy to Vercel and monitor logs
// ✅ Gradually enable blocking after testing
