/// <reference types="@cloudflare/workers-types" />

const SUPPORTED_LOCALES = ['en', 'zh', 'es', 'fr', 'de', 'ja', 'ru', 'ko', 'pt'] as const

interface QuizRecordRequest {
  quizId: string
  pagePath: string
  userId?: number
}

interface UserInfo {
  id?: number
  name?: string
  nick_name?: string
  email?: string
  [key: string]: unknown
}

interface UserData {
  user?: UserInfo
  [key: string]: unknown
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

    // Handle API routes
    if (url.pathname.startsWith('/cheatsheets/api/')) {
      return handleAPI(request, env)
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

async function handleAPI(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  const url = new URL(request.url)

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
      },
    })
  }

  // Handle POST /cheatsheets/api/quiz/record
  if (url.pathname === '/cheatsheets/api/quiz/record' && request.method === 'POST') {
    return handleRecordQuiz(request, env)
  }

  // Handle GET /cheatsheets/api/quiz/stats
  if (url.pathname === '/cheatsheets/api/quiz/stats' && request.method === 'GET') {
    return handleGetStats(request, env)
  }

  // Handle GET /cheatsheets/api/quiz/user-status
  if (url.pathname === '/cheatsheets/api/quiz/user-status' && request.method === 'GET') {
    return handleGetUserStatus(request, env)
  }

  // Handle GET /cheatsheets/api/user/me
  if (url.pathname === '/cheatsheets/api/user/me' && request.method === 'GET') {
    return handleUserMe(request, env)
  }

  return new Response(
    JSON.stringify({ error: 'Not found' }),
    {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    }
  )
}

async function getUserFromCookies(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<UserInfo | null> {
  try {
    const cookies = request.headers.get('Cookie')
    if (!cookies) {
      return null
    }

    // Hash the cookies to use as a cache key
    const encoder = new TextEncoder()
    const data = encoder.encode(cookies)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    // Key format: labexcheatsheets:session:${hashHex}
    const cacheKey = `labexcheatsheets:session:${hashHex}`

    // Try to get from KV first
    const cachedUser = await env.PYTHONCHEATSHEET_QUIZ_KV.get(cacheKey)
    if (cachedUser) {
      try {
        return JSON.parse(cachedUser) as UserInfo
      } catch (e) {
        console.error('Error parsing cached user:', e)
      }
    }

    const response = await fetch('https://labex.io/api/v2/users/me', {
      method: 'GET',
      headers: {
        'Cookie': cookies,
        'User-Agent': request.headers.get('User-Agent') || 'Cloudflare Worker',
        'Content-Type': 'application/json',
      },
    })

    if (response.ok) {
      const userData = await response.json() as UserData
      const user = userData.user || null

      if (user) {
        // Cache the user info in KV with a 10-minute expiration
        // We only cache if we got a valid user
        await env.PYTHONCHEATSHEET_QUIZ_KV.put(cacheKey, JSON.stringify(user), { expirationTtl: 600 })
      }

      return user
    }
    return null
  } catch (error) {
    console.error('Error fetching user from cookies:', error)
    return null
  }
}

async function handleRecordQuiz(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  try {
    const user = await getUserFromCookies(request, env)
    if (!user || !user.id) {
      return new Response(
        JSON.stringify({ error: 'Authentication required' }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }

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

    // Store user completion status: user:{userId}:quiz:{quizId}
    const userKey = `user:${user.id}:quiz:${normalizedPath}:${quizId}`
    await env.PYTHONCHEATSHEET_QUIZ_KV.put(userKey, '1')

    // Also maintain global count for stats
    const globalKey = `quiz:${normalizedPath}:${quizId}`
    const currentCount = await env.PYTHONCHEATSHEET_QUIZ_KV.get(globalKey)
    const count = currentCount ? parseInt(currentCount, 10) : 0
    const newCount = count + 1
    await env.PYTHONCHEATSHEET_QUIZ_KV.put(globalKey, newCount.toString())

    return new Response(
      JSON.stringify({
        success: true,
        quizId,
        pagePath: normalizedPath,
        userId: user.id,
        completed: true,
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

async function handleGetUserStatus(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  try {
    const user = await getUserFromCookies(request, env)
    if (!user || !user.id) {
      return new Response(
        JSON.stringify({ error: 'Authentication required' }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }

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
    const userKey = `user:${user.id}:quiz:${normalizedPath}:${quizId}`

    const completed = await env.PYTHONCHEATSHEET_QUIZ_KV.get(userKey)

    return new Response(
      JSON.stringify({
        success: true,
        quizId,
        pagePath: normalizedPath,
        userId: user.id,
        completed: completed === '1',
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Cache-Control': 'private, no-cache, must-revalidate',
        },
      }
    )
  } catch (error) {
    console.error('Error fetching user quiz status:', error)
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

async function handleUserMe(request: Request, env: { PYTHONCHEATSHEET_QUIZ_KV: KVNamespace }): Promise<Response> {
  try {
    const user = await getUserFromCookies(request, env)

    if (!user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
          },
        }
      )
    }

    return new Response(
      JSON.stringify({ user }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    )
  } catch (error) {
    console.error('Error in handleUserMe:', error)
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true',
        },
      }
    )
  }
}
