<script setup lang="ts">
defineProps<{
  repository?: string
}>()
</script>

<template>
  <footer class="mt-5 border-t border-slate-200 py-8 dark:border-slate-800">
    <div class="flex items-center justify-center">
      <a
        href="https://labex.io/learn"
        target="_blank"
        rel="noopener noreferrer"
        class="flex items-center gap-2 text-sm text-slate-600 transition-colors hover:text-primary-600 dark:text-slate-400 dark:hover:text-primary-400"
      >
        <span>LabEx</span>
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-4 w-4"
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
