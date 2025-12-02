import { useRoute } from 'vue-router'
import { SUPPORTED_LOCALES } from './useI18n'

interface QuizAPIResponse {
  success: boolean
  quizId: string
  pagePath: string
  count: number
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

export function useQuizTracking() {
  const route = useRoute()

  const recordQuizCompletion = async (quizId: string): Promise<number | null> => {
    try {
      const pagePath = normalizePathToEnglish(route.path)
      const basePath = import.meta.env.BASE_URL || '/cheatsheets/'
      const apiPath = basePath.endsWith('/') ? `${basePath}api/quiz/record` : `${basePath}/api/quiz/record`

      const response = await fetch(apiPath, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          quizId,
          pagePath,
        }),
      })

      if (!response.ok) {
        console.error('Failed to record quiz completion:', response.statusText)
        return null
      }

      const data = await response.json() as QuizAPIResponse
      return data.count || null
    } catch (error) {
      console.error('Error recording quiz completion:', error)
      return null
    }
  }

  const getQuizStats = async (quizId: string): Promise<number | null> => {
    try {
      const pagePath = normalizePathToEnglish(route.path)
      const basePath = import.meta.env.BASE_URL || '/cheatsheets/'
      const apiPath = basePath.endsWith('/') ? `${basePath}api/quiz/stats` : `${basePath}/api/quiz/stats`
      const url = new URL(apiPath, window.location.origin)
      url.searchParams.set('quizId', quizId)
      url.searchParams.set('pagePath', pagePath)

      const response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!response.ok) {
        console.error('Failed to fetch quiz stats:', response.statusText)
        return null
      }

      const data = await response.json() as QuizAPIResponse
      return data.count || 0
    } catch (error) {
      console.error('Error fetching quiz stats:', error)
      return null
    }
  }

  return {
    recordQuizCompletion,
    getQuizStats,
  }
}

