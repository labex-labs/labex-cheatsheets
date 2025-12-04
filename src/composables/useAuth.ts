import { ref } from 'vue'

interface UserInfo {
  id?: number
  name?: string
  nick_name?: string
  email?: string
  img_url?: string
  [key: string]: unknown
}

interface UserData {
  user?: UserInfo
  [key: string]: unknown
}

const user = ref<UserInfo | null>(null)
const isLoading = ref(false)
const isAuthenticated = ref(false)

export function useAuth() {
  const checkAuth = async (): Promise<void> => {
    if (typeof window === 'undefined') {
      return
    }

    isLoading.value = true
    try {
      const basePath = import.meta.env.BASE_URL || '/cheatsheets/'
      const apiPath = basePath.endsWith('/') ? `${basePath}api/user/me` : `${basePath}/api/user/me`

      const response = await fetch(apiPath, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (response.ok) {
        const userData = await response.json() as UserData
        user.value = userData.user || null
        isAuthenticated.value = true
      } else {
        user.value = null
        isAuthenticated.value = false
      }
    } catch (error) {
      console.error('Error checking auth status:', error)
      user.value = null
      isAuthenticated.value = false
    } finally {
      isLoading.value = false
    }
  }

  const login = (redirectPath?: string) => {
    if (typeof window !== 'undefined') {
      const currentPath = redirectPath || window.location.pathname
      const encodedPath = encodeURIComponent(currentPath)
      window.open(`https://labex.io/register?rd=${encodedPath}`, '_blank')
    }
  }

  return {
    user,
    isLoading,
    isAuthenticated,
    checkAuth,
    login,
  }
}

