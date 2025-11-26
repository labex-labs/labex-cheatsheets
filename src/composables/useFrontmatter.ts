import { ref, computed } from 'vue'

interface Frontmatter {
  title?: string
  description?: string
  publishedTime?: string
  modifiedTime?: string
  pdfUrl?: string
}

const currentFrontmatter = ref<Frontmatter>({})

export function useFrontmatter() {
  const setFrontmatter = (frontmatter: Frontmatter) => {
    currentFrontmatter.value = frontmatter
  }

  const getFrontmatter = computed(() => currentFrontmatter.value)

  const clearFrontmatter = () => {
    currentFrontmatter.value = {}
  }

  return {
    frontmatter: getFrontmatter,
    setFrontmatter,
    clearFrontmatter,
  }
}

