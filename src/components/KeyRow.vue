<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import { computed } from "vue";
import type { SshKey } from "../types";
import AppIcon from "./AppIcon.vue";
import StatusDot from "./StatusDot.vue";

const props = defineProps<{ keyItem: SshKey; selected: boolean; available: boolean }>();
const emit = defineEmits<{ select: [] }>();
const shortFingerprint = computed(() => {
  const value = props.keyItem.fingerprint;
  return value.length > 24 ? `${value.slice(0, 15)}…${value.slice(-6)}` : value;
});
const algorithm = computed(() => props.keyItem.algorithm.replace("sk-", "").replace("@openssh.com", "").replace("ssh-", "").toUpperCase());
</script>

<template>
  <div class="key-row" :class="{ selected }" role="button" tabindex="0" @click="emit('select')" @keyup.enter="emit('select')">
    <span class="key-row-icon"><AppIcon name="key" /></span>
    <span class="key-row-content">
      <span class="key-row-title">
        <strong>{{ keyItem.comment || "Resident key" }}</strong>
        <span class="ready-state" :class="{ locked: !available || !keyItem.enabled }"><StatusDot :status="available && keyItem.enabled ? 'success' : 'warning'" />{{ !keyItem.enabled ? "Disabled" : available ? "Ready" : "Locked" }}</span>
      </span>
      <span class="key-row-meta">{{ algorithm }} · {{ keyItem.backend === "fido2" ? "FIDO2" : keyItem.backend.replace("_", " ") }}</span>
      <code>{{ shortFingerprint }}</code>
    </span>
  </div>
</template>
