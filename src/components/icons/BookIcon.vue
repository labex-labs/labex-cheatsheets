<template>
  <svg
    aria-hidden="true"
    viewBox="0 0 32 32"
    fill="none"
    class="h-8 w-8 [--icon-foreground:theme(colors.slate.900)] [--icon-background:theme(colors.white)]"
  >
    <defs>
      <radialGradient
        id=":book:-gradient"
        cx="0"
        cy="0"
        r="1"
        gradientUnits="userSpaceOnUse"
        gradientTransform="matrix(0 21 -21 0 16 11)"
      >
        <stop stop-color="#2e7eee"></stop>
        <stop stop-color="#22D3EE" offset=".527"></stop>
        <stop stop-color="#818CF8" offset="1"></stop>
      </radialGradient>
      <radialGradient
        id=":book:-gradient-dark"
        cx="0"
        cy="0"
        r="1"
        gradientUnits="userSpaceOnUse"
        gradientTransform="matrix(0 24.5 -24.5 0 16 5.5)"
      >
        <stop stop-color="#2e7eee"></stop>
        <stop stop-color="#22D3EE" offset=".527"></stop>
        <stop stop-color="#818CF8" offset="1"></stop>
      </radialGradient>
    </defs>
    <g class="dark:hidden">
      <circle cx="16" cy="16" r="12" fill="url(#:book:-gradient)"></circle>
      <path
        d="M8 6h16a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2Z"
        class="fill-[var(--icon-background)] stroke-[color:var(--icon-foreground)]"
        fill-opacity="0.5"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      ></path>
      <path
        d="M16 6v20M8 14h16"
        class="stroke-[color:var(--icon-foreground)]"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      ></path>
    </g>
    <g class="hidden dark:inline">
      <path
        fill-rule="evenodd"
        clip-rule="evenodd"
        d="M8 5a3 3 0 0 0-3 3v16a3 3 0 0 0 3 3h16a3 3 0 0 0 3-3V8a3 3 0 0 0-3-3H8Zm-1 3a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V8Zm2 1v14h14V9H9Zm7 0v14h-7V9h7Z"
        fill="url(#:book:-gradient-dark)"
      ></path>
      <path
        d="M16 5v22M8 13h16"
        class="stroke-[color:var(--icon-foreground)]"
        stroke-width="1.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      ></path>
    </g>
  </svg>
</template>

