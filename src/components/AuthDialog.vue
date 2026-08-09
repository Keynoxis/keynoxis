<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { DeviceInfo } from "../types";
import AppIcon from "./AppIcon.vue";

const props = defineProps<{ mode: "pin" | "unlocking" | "touch" | "error" | "disconnected"; device?: DeviceInfo; devicePosition?: number; deviceCount?: number; sequential?: boolean; modelValue: string; busy?: boolean; error?: string; windowed?: boolean; timeout?: boolean; creatingKey?: boolean; deletingKey?: boolean; renamingKey?: boolean }>();
const emit = defineEmits<{ "update:modelValue": [value: string]; unlock: [] }>();
const deviceName = computed(() => props.device?.label || props.device?.product || "FIDO2 security key");
const devicePromptName = computed(() => {
  const base = props.device?.label || props.device?.product || "Security key";
  if (!props.deviceCount || props.deviceCount < 2) return base;
  return props.sequential
    ? `${base} · ${props.devicePosition || 1} of ${props.deviceCount}`
    : `${base} · #${props.devicePosition || 1}`;
});
const pinInput = ref<HTMLInputElement>();

async function focusPin() {
  if (props.mode !== "pin") return;
  await nextTick();
  window.setTimeout(() => pinInput.value?.focus(), 40);
}

watch(() => props.mode, focusPin);
onMounted(() => {
  focusPin();
  window.addEventListener("focus", focusPin);
});
onBeforeUnmount(() => window.removeEventListener("focus", focusPin));
</script>

<template>
  <div :class="windowed ? 'auth-window-content' : 'dialog-backdrop'" data-tauri-drag-region>
    <form class="auth-dialog" @submit.prevent="emit('unlock')">
      <div class="auth-device-icon" :class="{ waiting: mode === 'touch', pinning: mode === 'pin' || mode === 'unlocking', failed: mode === 'error' }"><AppIcon name="device" :size="27" /></div>
      <template v-if="mode === 'touch'">
        <h2>{{ deletingKey ? "Touch to confirm deletion" : "Touch your security key" }}</h2>
        <p>{{ devicePromptName }}</p>
        <div class="waiting-line" aria-live="polite">
          <span>Waiting for touch</span>
          <span class="waiting-dots" aria-hidden="true"><i></i><i></i><i></i></span>
        </div>
        <p class="keyboard-hint">Touch your key <span>·</span> <kbd>Esc</kbd> to close</p>
      </template>
      <template v-else-if="mode === 'disconnected'">
        <h2>Security key disconnected</h2>
        <p>Insert the FIDO2 security key to continue.</p>
        <p class="keyboard-hint"><kbd>Esc</kbd> to close</p>
      </template>
      <template v-else-if="mode === 'error'">
        <h2>{{ timeout ? "Touch timed out" : "Authentication failed" }}</h2>
        <p class="dialog-error-message">{{ timeout ? (deletingKey ? "No touch was detected. The SSH key was not deleted." : creatingKey ? "No touch was detected. The SSH key was not created." : "No touch was detected. The SSH request was cancelled.") : (error || "The security key refused the operation.") }}</p>
        <p class="keyboard-hint"><kbd>Esc</kbd> to close</p>
      </template>
      <template v-else>
        <h2 v-if="mode === 'pin' && !renamingKey && !deletingKey && !creatingKey" class="auth-pin-title">
          <span>Enter PIN</span>
          <span>{{ devicePromptName }}</span>
        </h2>
        <h2 v-else>{{ mode === "unlocking" ? (renamingKey ? "Renaming SSH key" : deletingKey ? "Authorizing key deletion" : creatingKey ? "Creating SSH key" : `Unlocking ${devicePromptName}`) : (renamingKey ? `Rename key on ${devicePromptName}` : deletingKey ? `Delete key from ${devicePromptName}` : `Create key on ${devicePromptName}`) }}</h2>
        <p><strong>{{ deviceName }}</strong><br><span>{{ device?.label && device?.product ? device.product : "FIDO2 Security Key" }}</span></p>
        <label for="security-key-pin">{{ renamingKey ? "Enter PIN to authorize the key name change" : deletingKey ? "Enter PIN to authorize permanent deletion" : creatingKey ? "Enter PIN to create the resident SSH identity" : "Enter PIN to unlock SSH identities" }}</label>
        <input
          ref="pinInput"
          id="security-key-pin"
          :value="modelValue"
          type="password"
          autocomplete="off"
          autofocus
          :disabled="mode === 'unlocking'"
          placeholder="••••••"
          @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
        />
        <p v-if="error" class="auth-error">{{ error }}</p>
        <p class="keyboard-hint">
          <template v-if="mode === 'unlocking'">Unlocking… <span>·</span> <kbd>Esc</kbd> to close</template>
          <template v-else>Enter PIN and press <kbd>Return</kbd> <span>·</span> <kbd>Esc</kbd> to close</template>
        </p>
      </template>
    </form>
  </div>
</template>
