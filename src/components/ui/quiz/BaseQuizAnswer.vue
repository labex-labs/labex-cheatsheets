<script setup lang="ts">
import { inject, computed } from 'vue'
import { useI18n } from '~/composables/useI18n'

const { t } = useI18n()

const props = defineProps<{
  value?: string
}>()

const quizState = inject<{
  selectedOption: { value: string | null }
  correctAnswer: { value: string | null }
  isAnswered: { value: boolean }
}>('quizState')

const isVisible = computed(() => {
  return quizState?.isAnswered.value === true
})

const answerValue = computed(() => {
  return props.value || quizState?.correctAnswer.value || ''
})
</script>

<template>
  <div
    v-if="isVisible"
    class="mt-4 rounded-lg border-2 border-primary-200 bg-gradient-to-br from-primary-50 to-primary-100/50 p-4 dark:border-primary-800 dark:from-slate-800/60 dark:to-primary-950/20"
  >
    <div class="flex items-center gap-2">
      <svg
        class="h-5 w-5 shrink-0 text-primary-600 dark:text-primary-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      </svg>
      <p
        v-if="answerValue"
        class="m-0 font-medium text-primary-900 dark:text-primary-300"
      >
        {{ t('quiz.correctAnswer') }}:
        <span class="font-bold">{{ answerValue }}</span>
      </p>
    </div>
    <div
      v-if="$slots.default"
      class="dark:!prose-code:text-slate-300 prose mt-2 text-primary-800 [--tw-prose-background:theme(colors.primary.50)] prose-a:!text-primary-900 prose-a:decoration-primary-600 prose-a:decoration-2 prose-a:underline-offset-0 prose-code:text-primary-900 dark:text-slate-300 dark:prose-a:!text-primary-400"
    >
      <p>
        <slot />
      </p>
    </div>
  </div>
</template>

