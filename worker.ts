/// <reference types="@cloudflare/workers-types" />

const SUPPORTED_LOCALES = ['en', 'zh', 'es', 'fr', 'de', 'ja', 'ru', 'ko', 'pt'] as const

interface QuizRecordRequest {
  quizId: string
  pagePath: string
}

/**
 * Normalize path to English version by removing language prefix
 * This ensures all language versions of the same page share the same quiz data
 */
function normalizePathToEnglish(path: string): string {
  const segments = path.split('/').filter(Boolean)
  if (segments.length > 0 && SUPPORTED_LOCALES.includes(segments[0] as typeof SUPPORTED_LOCALES[number])) {
    segments.shift()
    return segments.length > 0 ? '/' + segments.join('/') : '/'
  }
  return path
}

export default {
  async fetch(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace; ASSETS?: { fetch: (_req: Request) => Promise<Response> } }): Promise<Response> {
    const url = new URL(request.url)

    // Handle quiz API routes (support both /api/quiz/ and /cheatsheets/api/quiz/)
    if (url.pathname.startsWith('/api/quiz/') || url.pathname.startsWith('/cheatsheets/api/quiz/')) {
      return handleQuizAPI(request, env)
    }

    // For all other requests, let Cloudflare handle static assets
    // If ASSETS is available (for Workers with assets), use it; otherwise pass through
    if (env.ASSETS) {
      return env.ASSETS.fetch(request)
    }

    // Fallback: return the request as-is (Cloudflare will handle it)
    return fetch(request)
  },
}

async function handleQuizAPI(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  const url = new URL(request.url)

  // Normalize pathname by removing /cheatsheets prefix if present
  let pathname = url.pathname
  if (pathname.startsWith('/cheatsheets')) {
    pathname = pathname.slice('/cheatsheets'.length) || '/'
  }

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    })
  }

  // Handle POST /api/quiz/record
  if (pathname === '/api/quiz/record' && request.method === 'POST') {
    return handleRecordQuiz(request, env)
  }

  // Handle GET /api/quiz/stats
  if (pathname === '/api/quiz/stats' && request.method === 'GET') {
    return handleGetStats(request, env)
  }

  return new Response(
    JSON.stringify({ error: 'Not found' }),
    {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

async function handleRecordQuiz(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  try {
    const body = await request.json() as QuizRecordRequest
    const { quizId, pagePath } = body

    if (!quizId || !pagePath) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields: quizId and pagePath' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }

    const normalizedPath = normalizePathToEnglish(pagePath)
    const key = `quiz:${normalizedPath}:${quizId}`

    const currentCount = await env.PYTHONCHEATSHEET_QUIZ_KV.get(key)
    const count = currentCount ? parseInt(currentCount, 10) : 0
    const newCount = count + 1

    await env.PYTHONCHEATSHEET_QUIZ_KV.put(key, newCount.toString())

    return new Response(
      JSON.stringify({
        success: true,
        quizId,
        pagePath: normalizedPath,
        count: newCount,
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    )
  } catch (error) {
    console.error('Error recording quiz completion:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    )
  }
}

async function handleGetStats(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  try {
    const url = new URL(request.url)
    const quizId = url.searchParams.get('quizId')
    const pagePath = url.searchParams.get('pagePath')

    if (!quizId || !pagePath) {
      return new Response(
        JSON.stringify({ error: 'Missing required query parameters: quizId and pagePath' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }

    const normalizedPath = normalizePathToEnglish(pagePath)
    const key = `quiz:${normalizedPath}:${quizId}`

    const countStr = await env.PYTHONCHEATSHEET_QUIZ_KV.get(key)
    const count = countStr ? parseInt(countStr, 10) : 0

    return new Response(
      JSON.stringify({
        success: true,
        quizId,
        pagePath: normalizedPath,
        count,
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Cache-Control': 'public, max-age=60, s-maxage=60',
        },
      }
    )
  } catch (error) {
    console.error('Error fetching quiz stats:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
        },
      }
    )
  }
}

