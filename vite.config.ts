import path from 'path'
import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import Pages from 'vite-plugin-pages'
import Layouts from 'vite-plugin-vue-layouts'
import Components from 'unplugin-vue-components/vite'
import { HeadlessUiResolver } from 'unplugin-vue-components/resolvers'
import AutoImport from 'unplugin-auto-import/vite'
import { VitePWA } from 'vite-plugin-pwa'
import Markdown from 'unplugin-vue-markdown/vite'
import Prism from 'markdown-it-prism'
import LinkAttributes from 'markdown-it-link-attributes'
import anchor from 'markdown-it-anchor'
import string from 'string'
import { generateI18nSitemap } from './scripts/generate-i18n-sitemap'
import PrismLib from 'prismjs'


// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  process.env = { ...process.env, ...loadEnv(mode, process.cwd(), '') }

  const locales = ['zh', 'es', 'fr', 'de', 'ja', 'ru', 'ko', 'pt']
  const docSections = ['cheatsheets']

  const pageDirs: Array<{ dir: string; baseRoute: string }> = [
    { dir: 'src/pages', baseRoute: '' },
    { dir: 'docs/cheatsheets/en', baseRoute: '' },
  ]

  // Add multilingual directories for each locale and documentation section
  for (const locale of locales) {
    for (const section of docSections) {
      pageDirs.push({
        dir: `docs/${section}/${locale}`,
        baseRoute: `${locale}`,
      })
    }
  }

  return {
    base: '/cheatsheets/',
    build: {
      outDir: 'dist/cheatsheets',
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          manualChunks: undefined,
        },
      },
    },
    resolve: {
      alias: {
        '~/': `${path.resolve(__dirname, 'src')}/`,
        'vue-gtag': 'vue-gtag/dist/vue-gtag.esm-browser.js', // force ESM build for vue-gtag
      },
    },

    server: {
      proxy: {},
    },

    plugins: [
      vue({
        include: [/\.vue$/, /\.md$/],
        // reactivityTransform: true,
      }),

      // https://github.com/hannoeru/vite-plugin-pages
      Pages({
        extensions: ['vue', 'md'],
        dirs: pageDirs,
      }),

      // https://github.com/JohnCampionJr/vite-plugin-vue-layouts
      Layouts(),

      // https://github.com/antfu/unplugin-auto-import
      AutoImport({
        imports: ['vue', 'vue-router', '@vueuse/head', '@vueuse/core'],
        dts: 'src/auto-imports.d.ts',
        dirs: ['src/composables', 'src/store'],
        vueTemplate: true,
        eslintrc: {
          enabled: true,
        },
      }),

      // https://github.com/antfu/unplugin-vue-components
      Components({
        // allow auto load markdown components under `./src/components/`
        dirs: ['src/components'],
        extensions: ['vue', 'md'],
        // allow auto import and register components used in markdown
        include: [/\.vue$/, /\.vue\?vue/, /\.md$/],
        dts: 'src/components.d.ts',

        resolvers: [HeadlessUiResolver()],
      }),

      // https://github.com/antfu/vite-plugin-vue-markdown
      // https://prismjs.com/
      Markdown({
        headEnabled: true,
        markdownItSetup(md) {
          // Register 'output' as an alias for 'plaintext' to avoid Prism warnings
          PrismLib.languages.output = PrismLib.languages.plaintext
          // Register 'redis' as an alias for 'bash' to avoid Prism warnings
          PrismLib.languages.redis = PrismLib.languages.bash || PrismLib.languages.plaintext

          md.use(anchor, {
            slugify: (s: string) => string(s).slugify().toString(),
          })
          md.use(Prism, {})
          md.use(LinkAttributes, {
            matcher: (link: string) => /^https?:\/\//.test(link),
            attrs: {
              target: '_blank',
              rel: 'noopener',
            },
          })
        },
      }),

      // https://github.com/antfu/vite-plugin-pwa
      VitePWA({
        registerType: 'autoUpdate',
        includeAssets: ['favicon.svg', 'safari-pinned-tab.svg'],
        workbox: {
          // 使用 NetworkFirst 策略处理导航请求（HTML 页面），确保优先从网络获取最新内容
          runtimeCaching: [
            {
              // 匹配所有 HTML 页面请求（包括根路径和所有路由）
              // 使用 NetworkFirst 确保优先从网络获取最新内容
              urlPattern: ({ request, url }: { request: Request; url: URL }) =>
                request.mode === 'navigate' ||
                request.destination === 'document' ||
                url.pathname.endsWith('.html') ||
                (!url.pathname.includes('.') && request.headers.get('accept')?.includes('text/html')),
              handler: 'NetworkFirst',
              options: {
                cacheName: 'html-cache',
                expiration: {
                  maxEntries: 10,
                  maxAgeSeconds: 60 * 60, // 1 小时，确保 HTML 不会缓存太久
                },
                networkTimeoutSeconds: 3, // 3 秒超时后使用缓存
              },
            },
            // 对于静态资源（JS/CSS），使用 StaleWhileRevalidate，优先使用缓存但后台更新
            {
              urlPattern: ({ request }: { request: Request }) =>
                request.destination === 'script' || request.destination === 'style',
              handler: 'StaleWhileRevalidate',
              options: {
                cacheName: 'static-resources',
                expiration: {
                  maxEntries: 50,
                  maxAgeSeconds: 60 * 60 * 24 * 7, // 7 天
                },
              },
            },
            // 对于图片和其他静态资源，使用 CacheFirst
            {
              urlPattern: ({ request }: { request: Request }) =>
                request.destination === 'image' ||
                request.destination === 'font' ||
                /\.(png|jpg|jpeg|svg|gif|webp|ico|woff|woff2|ttf|eot)$/i.test(request.url),
              handler: 'CacheFirst',
              options: {
                cacheName: 'images-cache',
                expiration: {
                  maxEntries: 100,
                  maxAgeSeconds: 60 * 60 * 24 * 30, // 30 天
                },
              },
            },
          ],
          // 跳过等待，立即激活新的 Service Worker
          skipWaiting: true,
          // 立即控制所有客户端
          clientsClaim: true,
          // 清理旧的缓存
          cleanupOutdatedCaches: true,
        },
        manifest: {
          name: 'Python Cheatsheet',
          short_name: 'Python Cheatsheet',
          theme_color: '#ffffff',
          icons: [
            {
              src: 'android-chrome-192x192.png',
              sizes: '192x192',
              type: 'image/png',
            },
            {
              src: 'android-chrome-512x512.png',
              sizes: '512x512',
              type: 'image/png',
            },
            {
              src: 'android-chrome-512x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'any maskable',
            },
          ],
        },
      }),
    ],

    // https://github.com/antfu/vite-ssg
    ssgOptions: {
      script: 'async',
      formatting: 'minify',
      format: 'esm', // changed from 'cjs' to 'esm' to fix ESM/CJS compatibility
      async onFinished() {
        const baseUrl = process.env.VITE_BASE_URL || 'labex.io'
        const hostname = baseUrl.startsWith('http') ? baseUrl : `https://${baseUrl}`
        // Append /cheatsheets to hostname for sitemap generation
        const sitemapHostname = hostname.endsWith('/') ? `${hostname}cheatsheets` : `${hostname}/cheatsheets`
        await generateI18nSitemap(sitemapHostname, 'dist/cheatsheets')
      },
    },

    // https://github.com/vitest-dev/vitest
    test: {
      environment: 'jsdom',
      deps: {
        inline: ['@vue', '@vueuse'],
      },
    },
  }
})
