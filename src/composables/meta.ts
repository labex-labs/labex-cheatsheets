import { SUPPORTED_LOCALES, useI18n } from './useI18n'
import { useFrontmatter } from './useFrontmatter'

interface Frontmatter {
  title?: string
  description?: string
  publishedTime?: string
  modifiedTime?: string
}

export function useMeta() {
  const route = useRoute()
  const { t, currentLocale } = useI18n()
  const { frontmatter: runtimeFrontmatter } = useFrontmatter()
  const configuredBaseUrl = import.meta.env.VITE_BASE_URL || 'labex.io'
  const base_path = import.meta.env.BASE_URL || '/cheatsheets/'
  const normalizedBaseUrl = configuredBaseUrl.startsWith('http')
    ? configuredBaseUrl
    : `https://${configuredBaseUrl}`
  const siteUrl = new URL(normalizedBaseUrl)
  const siteOrigin = siteUrl.origin
  const appBasePath = base_path.endsWith('/') ? base_path.slice(0, -1) : base_path
  const configuredPathPrefix = siteUrl.pathname === '/' ? '' : siteUrl.pathname.replace(/\/$/, '')
  const fullBasePath = configuredPathPrefix.endsWith(appBasePath)
    ? configuredPathPrefix
    : `${configuredPathPrefix}${appBasePath}`

  const joinSiteUrl = (path: string): string => {
    if (path === '/' || path === '') {
      return `${siteOrigin}${fullBasePath}/`
    }

    return `${siteOrigin}${fullBasePath}${path.startsWith('/') ? path : `/${path}`}`
  }

  const getBasePath = (path: string): string => {
    const normalizedBasePath = base_path.endsWith('/') ? base_path.slice(0, -1) : base_path
    let relativePath = path
    if (normalizedBasePath && path.startsWith(normalizedBasePath)) {
      relativePath = path.slice(normalizedBasePath.length)
    }

    const segments = relativePath.split('/').filter(Boolean)
    if (segments.length > 0 && SUPPORTED_LOCALES.includes(segments[0] as typeof SUPPORTED_LOCALES[number])) {
      segments.shift()
      return segments.length > 0 ? '/' + segments.join('/') : '/'
    }
    return relativePath || '/'
  }

  const buildLocalizedPath = (locale: typeof SUPPORTED_LOCALES[number], path: string): string => {
    if (locale === 'en') {
      return path === '' ? '/' : path
    }

    if (path === '/' || path === '') {
      return `/${locale}`
    }

    return `/${locale}${path}`
  }

  // Get frontmatter from multiple sources (priority: runtime > route.meta > empty)
  // Note: unplugin-vue-markdown may expose frontmatter via route.meta.frontmatter
  // Runtime frontmatter is set by markdown components via useFrontmatter composable
  const frontmatter = computed<Frontmatter>(() => {
    const routeFrontmatter = (route.meta?.frontmatter as Frontmatter) || {}
    return {
      ...routeFrontmatter,
      ...runtimeFrontmatter.value,
    }
  })

  // Helper function to generate page title from route path
  const getPageTitleFromPath = (path: string): string => {
    // Remove base_path if it exists at the start of the path
    const normalizedBasePath = base_path.endsWith('/') ? base_path.slice(0, -1) : base_path
    let relativePath = path
    if (normalizedBasePath && path.startsWith(normalizedBasePath)) {
      relativePath = path.slice(normalizedBasePath.length)
    }

    const segments = relativePath.split('/').filter(Boolean)
    if (segments.length === 0) return ''

    // Remove locale prefix if present
    const firstSegment = segments[0]
    if (SUPPORTED_LOCALES.includes(firstSegment as typeof SUPPORTED_LOCALES[number])) {
      segments.shift()
    }

    if (segments.length === 0) return ''

    // Capitalize and format the last segment
    const lastSegment = segments[segments.length - 1]
    return lastSegment
      .split('-')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ') + ' Cheat Sheet'
  }

  // Generate page-specific title: use frontmatter title if available, otherwise infer from path
  const pageTitle = computed(() => {
    if (frontmatter.value.title) {
      return frontmatter.value.title
    }

    // Try to infer from route path
    const inferredTitle = getPageTitleFromPath(route.path)
    if (inferredTitle) {
      return inferredTitle
    }

    return t('meta.title')
  })

  // Generate page-specific description: use frontmatter description if available
  const pageDescription = computed(() => {
    if (frontmatter.value.description) {
      return frontmatter.value.description
    }

    const basePath = getBasePath(route.path)
    if (basePath === '/' || basePath === '') {
      return t('home.description')
    }

    // Generate a basic description from title if available
    const inferredTitle = getPageTitleFromPath(route.path)
    if (inferredTitle) {
      return `Learn ${inferredTitle.replace(' Cheat Sheet', '')} with our comprehensive cheat sheet covering essential commands, concepts, and best practices.`
    }

    return t('meta.description')
  })

  const description = computed(() => pageDescription.value)
  const cardImage = computed(() => {
    return joinSiteUrl('/screenshots/labex-cheatsheets.png')
  })
  const themeColor = computed(() => (isDark.value ? '#1f2937' : '#ffffff'))
  const url = computed(() => {
    return joinSiteUrl(route.path)
  })

  // Generate breadcrumb list for structured data
  const generateBreadcrumbList = computed(() => {
    const basePath = getBasePath(route.path)
    const segments = basePath.split('/').filter(Boolean)
    const breadcrumbs = [
      {
        '@type': 'ListItem',
        position: 1,
        name: 'Home',
        item: joinSiteUrl('/'),
      },
    ]

    let currentPath = ''
    segments.forEach((segment, index) => {
      currentPath += `/${segment}`
      breadcrumbs.push({
        '@type': 'ListItem',
        position: index + 2,
        name: segment.charAt(0).toUpperCase() + segment.slice(1).replace(/-/g, ' '),
        item: joinSiteUrl(currentPath),
      })
    })

    return {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: breadcrumbs,
    }
  })

  // Generate structured data (JSON-LD)
  const generateStructuredData = computed(() => {
    const basePath = getBasePath(route.path)
    const isHomePage = basePath === '/' || basePath === ''

    // WebPage schema for all pages
    const webPageSchema = {
      '@context': 'https://schema.org',
      '@type': 'WebPage',
      name: pageTitle.value,
      description: pageDescription.value,
      url: url.value,
      inLanguage: currentLocale.value,
      isPartOf: {
        '@type': 'WebSite',
        name: 'LabEx Cheat Sheets',
        url: joinSiteUrl('/'),
      },
      publisher: {
        '@type': 'Organization',
        name: 'LabEx',
        url: 'https://labex.io',
      },
    }

    // Article schema for content pages (not home page)
    if (!isHomePage && frontmatter.value.title) {
      const articleSchema = {
        '@context': 'https://schema.org',
        '@type': 'Article',
        headline: frontmatter.value.title,
        description: frontmatter.value.description || pageDescription.value,
        url: url.value,
        inLanguage: currentLocale.value,
        author: {
          '@type': 'Organization',
          name: 'LabEx',
          url: 'https://labex.io',
        },
        publisher: {
          '@type': 'Organization',
          name: 'LabEx',
          url: 'https://labex.io',
          logo: {
            '@type': 'ImageObject',
            url: joinSiteUrl('/android-chrome-192x192.png'),
          },
        },
        mainEntityOfPage: {
          '@type': 'WebPage',
          '@id': url.value,
        },
        ...(frontmatter.value.publishedTime && {
          datePublished: frontmatter.value.publishedTime,
        }),
        ...(frontmatter.value.modifiedTime && {
          dateModified: frontmatter.value.modifiedTime,
        }),
      }
      return [webPageSchema, articleSchema, generateBreadcrumbList.value]
    }

    return [webPageSchema, generateBreadcrumbList.value]
  })

  // Generate hreflang links
  const generateHreflangLinks = computed(() => {
    const basePath = getBasePath(route.path)
    const links = []

    // Generate hreflang link for each supported locale
    for (const locale of SUPPORTED_LOCALES) {
      const localePath = buildLocalizedPath(locale, basePath)
      const localeUrl = joinSiteUrl(localePath)
      links.push({
        rel: 'alternate',
        hreflang: locale,
        href: localeUrl,
      })
    }

    // Add x-default (points to default language version)
    const defaultPath = basePath
    const defaultUrl = joinSiteUrl(defaultPath)
    links.push({
      rel: 'alternate',
      hreflang: 'x-default',
      href: defaultUrl,
    })

    return links
  })

  const title = computed(() => pageTitle.value)
  const keywords = computed(() => t('meta.keywords'))

  // Build meta tags array
  const metaTags = computed(() => {
    const tags = [
      { name: 'theme-color', content: themeColor.value },
      { name: 'description', content: pageDescription.value },
      { name: 'author', content: 'LabEx' },
      { name: 'keywords', content: keywords.value },
      { property: 'og:title', content: pageTitle.value },
      { property: 'og:description', content: pageDescription.value },
      { property: 'og:url', content: url.value },
      { property: 'og:type', content: frontmatter.value.title ? 'article' : 'website' },
      { property: 'og:image', content: cardImage.value },
      { property: 'og:image:width', content: '1200' },
      { property: 'og:image:height', content: '630' },
      { property: 'og:image:alt', content: pageTitle.value },
      { property: 'og:site_name', content: 'LabEx Cheat Sheets' },
      { name: 'twitter:card', content: 'summary_large_image' },
      { name: 'twitter:title', content: pageTitle.value },
      { name: 'twitter:description', content: pageDescription.value },
      { name: 'twitter:image', content: cardImage.value },
      { name: 'twitter:site', content: '@labex_io' },
      { name: 'twitter:creator', content: '@labex_io' },
    ]

    // Add article meta tags if it's a content page
    if (frontmatter.value.title) {
      if (frontmatter.value.publishedTime) {
        tags.push({ property: 'article:published_time', content: frontmatter.value.publishedTime })
      }
      if (frontmatter.value.modifiedTime) {
        tags.push({ property: 'article:modified_time', content: frontmatter.value.modifiedTime })
      }
      tags.push({ property: 'article:author', content: 'LabEx' })
    }

    return tags
  })

  const meta = computed(() => ({
    title: title.value,
    description: description.value,
    htmlAttrs: {
      lang: currentLocale.value,
    },
    meta: metaTags.value,
    link: [
      { rel: 'canonical', href: url.value },
      ...generateHreflangLinks.value,
    ],
    script: generateStructuredData.value.map((schema) => ({
      type: 'application/ld+json',
      children: JSON.stringify(schema),
    })),
  }))

  return { meta, description }
}
