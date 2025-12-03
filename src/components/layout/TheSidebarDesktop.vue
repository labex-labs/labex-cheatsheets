<script setup lang="ts">
import { computed } from 'vue'

const navigation = useNavigationStore()
const { t, localePath, getNavigationName } = useI18n()

const mainNavigation = computed(() => {
  return navigation.mainNavigation.map((item) => ({
    ...item,
    name: item.path === '/' ? t('sidebar.gettingStarted') : item.name,
    path: localePath(item.path),
  }))
})

const cheatsheetNavigation = computed(() => {
  return navigation.cheatsheetNavigation.map((item) => ({
    ...item,
    name: getNavigationName(item.path, item.name),
    path: localePath(item.path),
  }))
})
</script>

<template>
  <div class="flex min-h-full flex-col">
    <nav class="flex-1 pb-20">
      <the-sidebar-navigation
        :navigation="mainNavigation"
        :section-name="t('sidebar.introduction')"
      />

      <the-sidebar-navigation
        :navigation="cheatsheetNavigation"
        :section-name="t('sidebar.cheatsheet')"
      />
    </nav>

    <!-- Fixed action buttons at bottom -->
    <div
      class="sticky bottom-0 mt-auto flex items-center justify-start gap-4 border-t border-slate-200 bg-white/90 py-4 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90"
    >
      <base-reader-mode />
      <a
        target="_blank"
        href="https://github.com/labex-labs/labex-cheatsheets"
        rel="noreferrer"
        class="flex items-center"
        :title="t('navbar.repositoryLink')"
      >
        <github-icon />
        <span class="sr-only">{{ t('navbar.repositoryLink') }}</span>
      </a>
      <base-theme-toggle />
    </div>
  </div>
</template>
