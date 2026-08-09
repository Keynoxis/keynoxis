<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
withDefaults(defineProps<{ size?: number }>(), { size: 24 });
</script>

<template>
  <svg class="brand-mark" :width="size" :height="size" viewBox="0 0 24 24" role="img" aria-label="Keynoxis">
    <defs>
      <linearGradient id="brand-metal" x1="7" y1="6" x2="17" y2="18" gradientUnits="userSpaceOnUse">
        <stop stop-color="#f2f5f7" />
        <stop offset=".5" stop-color="#b9c3cc" />
        <stop offset="1" stop-color="#7d8994" />
      </linearGradient>
    </defs>
    <rect x=".5" y=".5" width="23" height="23" rx="6" fill="#11151a" stroke="#fff" stroke-opacity=".14" />
    <rect x="5" y="5" width="14" height="14" rx="4" fill="#151a1f" stroke="#fff" stroke-opacity=".12" />
    <path d="M7.8 7.2h2.5v3.7l4.1-3.7h3.3l-5 4.3 5 4.8h-3.4l-4-4v4H7.8z" fill="url(#brand-metal)" />
    <circle cx="18.7" cy="6.8" r="1" fill="#90c99b" />
  </svg>
</template>
