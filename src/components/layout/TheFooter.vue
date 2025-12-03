<script setup lang="ts">
defineProps<{
  repository?: string
}>()

const { t } = useI18n()
</script>

<template>
  <footer class="mt-5 border-t border-slate-200 py-8 dark:border-slate-800">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-4">
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
      <a
        href="https://labex.io/learn"
        target="_blank"
        rel="noopener noreferrer"
        class="flex items-center gap-2 text-slate-500 transition-colors hover:text-slate-600 dark:text-slate-400 dark:hover:text-slate-300"
      >
        <span class="text-sm">LabEx</span>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-5 w-5 sm:h-6 sm:w-6"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
          />
        </svg>
      </a>
    </div>
  </footer>
</template>
