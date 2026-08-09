<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import AppIcon from "./AppIcon.vue";
import BrandMark from "./BrandMark.vue";
import StatusDot from "./StatusDot.vue";

defineProps<{ active: string; agentRunning: boolean; identities: number }>();
defineEmits<{ navigate: [screen: string] }>();
const navigation = [
  { id: "agent", label: "Agent", icon: "activity" },
  { id: "keys", label: "Keys", icon: "key" },
  { id: "devices", label: "Devices", icon: "device" },
  { id: "activity", label: "Activity", icon: "activity" },
  { id: "settings", label: "Settings", icon: "settings" }
];
</script>

<template>
  <aside class="sidebar" data-tauri-drag-region>
    <div class="sidebar-brand" data-tauri-drag-region>
      <BrandMark />
      <span>Keynoxis</span>
    </div>
    <nav>
      <button v-for="item in navigation" :key="item.id" :class="{ active: active === item.id }" @click="$emit('navigate', item.id)">
        <AppIcon :name="item.icon" />
        {{ item.label }}
      </button>
    </nav>
    <div class="sidebar-status">
      <div><StatusDot :status="agentRunning ? 'success' : 'danger'" />{{ agentRunning ? "Agent Running" : "Agent Stopped" }}</div>
      <p>{{ identities }} {{ identities === 1 ? "identity" : "identities" }}</p>
    </div>
  </aside>
</template>
