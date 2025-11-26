<script setup lang="ts">
import { onMounted } from 'vue'

const robotsContent = `User-agent: *
Allow: /`

useHead({
  htmlAttrs: {
    lang: '',
  },
  meta: [
    {
      'http-equiv': 'Content-Type',
      content: 'text/plain; charset=utf-8',
    },
  ],
})

onMounted(() => {
  const pre = document.querySelector('pre')
  if (pre) {
    pre.style.margin = '0'
    pre.style.padding = '0'
    pre.style.fontFamily = 'monospace'
    pre.style.whiteSpace = 'pre'
  }
})
</script>

<template>
  <pre>{{ robotsContent }}</pre>
</template>

<route lang="yaml">
meta:
  layout: empty
</route>
