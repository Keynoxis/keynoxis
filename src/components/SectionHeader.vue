<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
defineProps<{ title: string; description?: string }>();
</script>
<template>
  <header class="section-header" data-tauri-drag-region>
    <div data-tauri-drag-region>
      <h1 data-tauri-drag-region>{{ title }}</h1>
      <p v-if="description">{{ description }}</p>
    </div>
    <div class="section-actions"><slot /></div>
  </header>
</template>
