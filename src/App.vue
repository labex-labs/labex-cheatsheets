<script setup>
import { watch } from 'vue'
import { useRoute } from 'vue-router'
import { useFrontmatter } from './composables/useFrontmatter'

const route = useRoute()
const { meta } = useMeta()
const { clearFrontmatter } = useFrontmatter()

useHead(meta)
useScrollBehavior()

// Clear frontmatter when route changes (markdown components will set new frontmatter)
watch(() => route.path, () => {
  clearFrontmatter()
})

// Inject Google Analytics script if VITE_GTAG is configured
const gTag = import.meta.env.VITE_GTAG
if (gTag && gTag !== 'tag' && gTag.trim() !== '') {
  useHead({
    script: [
      {
        src: `https://www.googletagmanager.com/gtag/js?id=${gTag}`,
        async: true,
      },
      {
        innerHTML: `
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());
          gtag('config', '${gTag}');
        `,
      },
    ],
  })
}
</script>

<template>
  <RouterView />
</template>
