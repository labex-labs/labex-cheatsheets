<script setup lang="ts">
import { breakpointsTailwind } from '@vueuse/core'
import ArrowIcon from '~/components/icons/ArrowIcon.vue'
import ReferenceIcon from '~/components/icons/ReferenceIcon.vue'
import PluginIcon from '~/components/icons/PluginIcon.vue'
import WarningIcon from '~/components/icons/WarningIcon.vue'
import { computed } from 'vue'

const { t } = useI18n()

const cardLinks = computed(() => [
  {
    path: '/linux',
    name: t('home.cardLinks.linux'),
    description: t('home.cardLinks.linuxDesc'),
    icon: ReferenceIcon,
    external: false,
  },
  {
    path: '/devops',
    name: t('home.cardLinks.devops'),
    description: t('home.cardLinks.devopsDesc'),
    icon: PluginIcon,
    external: false,
  },
  {
    path: '/cybersecurity',
    name: t('home.cardLinks.cybersecurity'),
    description: t('home.cardLinks.cybersecurityDesc'),
    icon: WarningIcon,
    external: false,
  },
  {
    path: 'https://github.com/labex-labs/labex-cheatsheets',
    name: t('home.cardLinks.viewOnGithub'),
    description: t('home.cardLinks.viewOnGithubDesc'),
    icon: ArrowIcon,
    external: true,
  },
])

const { description } = useMeta()
const breakpoints = useBreakpoints(breakpointsTailwind)
const smAndLarger = breakpoints.greater('sm')
</script>

<template>
  <article>
    <prose>
      <base-title
        v-if="smAndLarger"
        id="labex-cheatsheets"
        :title="t('home.title')"
        :description="description"
      >
        {{ t('home.title') }}
      </base-title>
      <h1
        v-else
        class="mb-2 bg-gradient-to-r from-secondary-400 to-green-400 bg-clip-text text-center font-display text-4xl font-medium tracking-tight text-transparent dark:from-primary-400 dark:via-teal-300 dark:to-orange-300"
      >
        {{ t('home.title') }}
      </h1>
    </prose>

    <prose>
      <p>
        {{ t('home.description') }}
      </p>
    </prose>

    <div className="not-prose my-8 grid grid-cols-1 gap-6 sm:grid-cols-2">
      <base-link-card
        v-for="link in cardLinks"
        :key="link.path"
        :title="link.name"
        :description="link.description"
        :path="link.path"
        :icon="link.icon"
        :is-external="link.external"
      />
    </div>
  </article>
</template>
