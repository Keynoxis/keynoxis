<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
withDefaults(defineProps<{ status?: "success" | "warning" | "danger" | "neutral"; pulse?: boolean }>(), { status: "neutral", pulse: false });
</script>
<template><span class="status-dot" :class="[status, { pulse }]" aria-hidden="true"></span></template>
