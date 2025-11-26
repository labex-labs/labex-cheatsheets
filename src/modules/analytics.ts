import VueGtag from 'vue-gtag-next'
import { type UserModule } from '~/types'

export const install: UserModule = ({ app, router }) => {
  const gTag = import.meta.env.VITE_GTAG
  // If VITE_GTAG is configured and the value is valid, enable GTAG tracking
  if (gTag && gTag !== 'tag' && gTag.trim() !== '') {
    // Use vue-gtag-next for both client and server-side rendering
    // It will handle script injection properly for SSG
    app.use(VueGtag, {
      config: { id: gTag },
      router
    } as any)
  }
}
