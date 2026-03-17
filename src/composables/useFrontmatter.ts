import { computed, inject, provide, ref, type InjectionKey, type Ref } from 'vue'

interface Frontmatter {
  title?: string
  description?: string
  publishedTime?: string
  modifiedTime?: string
  pdfUrl?: string
}

const frontmatterKey: InjectionKey<Ref<Frontmatter>> = Symbol('frontmatter')

function createFrontmatterApi(state: Ref<Frontmatter>) {
  const setFrontmatter = (frontmatter: Frontmatter) => {
    state.value = frontmatter
  }

  const getFrontmatter = computed(() => state.value)

  const clearFrontmatter = () => {
    state.value = {}
  }

  return {
    frontmatter: getFrontmatter,
    setFrontmatter,
    clearFrontmatter,
  }
}

export function provideFrontmatter() {
  const state = ref<Frontmatter>({})
  provide(frontmatterKey, state)
  return createFrontmatterApi(state)
}

export function useFrontmatter() {
  const state = inject(frontmatterKey, ref<Frontmatter>({}))
  return createFrontmatterApi(state)
}
