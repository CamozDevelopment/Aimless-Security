// app/api/test-with/route.js
export const runtime = 'nodejs';

export async function POST(request) {
  try {
    // Dynamic import with error catching
    const { Aimless } = await import('aimless-security');
    
    const aimless = new Aimless({
      rasp: {
        enabled: true,
        blockMode: false  // ← DISABLE blocking temporarily
      }
    });
    
    const body = await request.json();
    
    // Just analyze, don't block
    const threats = aimless.analyze({
      method: 'POST',
      body: body
    });
    
    return Response.json({
      success: true,
      threats: threats,  // See what it detected
      input: body
    });
    
  } catch (error) {
    // Return the ACTUAL error
    return Response.json({
      error: error.message,
      stack: error.stack,
      name: error.name
    }, { status: 500 });
  }
}