<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
defineProps<{ name: string; size?: number }>();
</script>

<template>
  <svg class="app-icon" :width="size || 17" :height="size || 17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <template v-if="name === 'key'">
      <circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-3 3 2 2m-5 1 2 2"/>
    </template>
    <template v-else-if="name === 'device'">
      <rect x="6" y="3" width="12" height="18" rx="3"/><path d="M10 7h4M10 17h4"/>
    </template>
    <template v-else-if="name === 'activity'">
      <path d="M3 12h4l2.2-6 4.1 12 2.2-6H21"/>
    </template>
    <template v-else-if="name === 'settings'">
      <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>
    </template>
    <template v-else-if="name === 'copy'">
      <rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>
    </template>
    <template v-else-if="name === 'chip'">
      <rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 1v5m6-5v5M9 18v5m6-5v5M1 9h5m-5 6h5m12-6h5m-5 6h5"/><rect x="10" y="10" width="4" height="4" rx=".5"/>
    </template>
    <template v-else-if="name === 'shield'">
      <path d="M12 3 5 6v5c0 4.7 2.9 8.1 7 10 4.1-1.9 7-5.3 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>
    </template>
    <template v-else-if="name === 'fingerprint'">
      <path d="M7.4 17.5A8 8 0 0 1 6 13v-1a6 6 0 0 1 12 0v1m-8 8a10 10 0 0 1-2-6v-3a4 4 0 0 1 8 0v2a12 12 0 0 0 1.1 5M12 22a12 12 0 0 1-2-7v-3a2 2 0 0 1 4 0v2a14 14 0 0 0 1 5.2M4.5 17A10 10 0 0 1 4 13v-1a8 8 0 0 1 15.4-3"/>
    </template>
    <template v-else-if="name === 'plus'">
      <path d="M12 5v14M5 12h14"/>
    </template>
    <template v-else-if="name === 'chevron'">
      <path d="m9 18 6-6-6-6"/>
    </template>
    <template v-else-if="name === 'more'">
      <circle cx="5" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1" fill="currentColor" stroke="none"/>
    </template>
    <template v-else>
      <circle cx="12" cy="12" r="8"/>
    </template>
  </svg>
</template>
