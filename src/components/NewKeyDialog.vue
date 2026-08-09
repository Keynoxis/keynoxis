<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import type { DeviceInfo } from "../types";
import AppIcon from "./AppIcon.vue";

type Backend = "secure_enclave" | "fido2";

const props = defineProps<{ open: boolean; busy?: boolean; error?: string; devices?: DeviceInfo[]; activeDevicePath?: string }>();
const emit = defineEmits<{ close: []; create: [name: string, backend: Backend, algorithm: string, devicePath?: string] }>();
const name = ref("");
const backend = ref<Backend>("secure_enclave");
const devicePath = ref<string>();
const fidoAlgorithm = ref("sk-ssh-ed25519@openssh.com");
const input = ref<HTMLInputElement>();
const fidoDevices = computed(() => (props.devices || []).filter(device => device.fido2));
const selectedDevice = computed(() => fidoDevices.value.find(device => device.path === devicePath.value));
const availableAlgorithms = computed(() => selectedDevice.value?.algorithms.length
  ? selectedDevice.value.algorithms
  : ["ED25519-SK", "ECDSA-SK"]);
const algorithm = computed(() => backend.value === "fido2" ? fidoAlgorithm.value : "ECDSA P-256");
const yubikeyConnected = computed(() => fidoDevices.value.length > 0);

function deviceName(device: DeviceInfo, index: number) {
  const base = device.label || device.product || "FIDO2 security key";
  return fidoDevices.value.length > 1 ? `${base} · #${index + 1}` : base;
}

watch(() => props.open, async open => {
  if (!open) return;
  name.value = "";
  backend.value = "secure_enclave";
  devicePath.value = props.activeDevicePath && fidoDevices.value.some(device => device.path === props.activeDevicePath)
    ? props.activeDevicePath
    : fidoDevices.value[0]?.path;
  fidoAlgorithm.value = availableAlgorithms.value.includes("ED25519-SK") ? "ED25519-SK" : availableAlgorithms.value[0] || "ED25519-SK";
  await nextTick();
  input.value?.focus();
});

watch(devicePath, () => {
  if (!availableAlgorithms.value.includes(fidoAlgorithm.value)) {
    fidoAlgorithm.value = availableAlgorithms.value.includes("ED25519-SK")
      ? "ED25519-SK"
      : availableAlgorithms.value[0] || "ED25519-SK";
  }
});

function submit() {
  const value = name.value.trim();
  if (value && !props.busy && (backend.value !== "fido2" || yubikeyConnected.value)) {
    const wireAlgorithm = fidoAlgorithm.value === "ECDSA-SK"
      ? "sk-ecdsa-sha2-nistp256@openssh.com"
      : "sk-ssh-ed25519@openssh.com";
    emit("create", value, backend.value, wireAlgorithm, devicePath.value);
  }
}
</script>

<template>
  <div v-if="open" class="new-key-backdrop" @mousedown.self="emit('close')">
    <form class="new-key-dialog" @submit.prevent="submit">
      <div class="new-key-heading">
        <span class="new-key-icon"><AppIcon name="key" :size="19" /></span>
        <div><h2>Create SSH Key</h2><p>Choose where the hardware-backed SSH identity will live.</p></div>
      </div>

      <label class="new-key-field">
        <span>Key name</span>
        <input ref="input" v-model="name" maxlength="64" placeholder="e.g. Homelab, Work or Cloud" autocomplete="off" @keyup.esc="emit('close')" />
      </label>

      <button type="button" class="storage-choice" :class="{ selected: backend === 'secure_enclave' }" @click="backend = 'secure_enclave'">
        <span class="provider-icon"><AppIcon name="chip" /></span>
        <span><strong>Secure Enclave</strong><small>Apple Silicon hardware-backed storage</small></span>
        <span v-if="backend === 'secure_enclave'" class="choice-check">✓</span>
      </button>

      <button
        v-for="(device, index) in fidoDevices"
        :key="device.path"
        type="button"
        class="storage-choice"
        :class="{ selected: backend === 'fido2' && devicePath === device.path }"
        @click="backend = 'fido2'; devicePath = device.path"
      >
        <span class="provider-icon"><AppIcon name="device" /></span>
        <span>
          <strong>{{ deviceName(device, index) }}</strong>
          <small>{{ device.firmware ? `FIDO2 · Firmware ${device.firmware}` : "FIDO2 security key" }}<template v-if="device.resident_credentials_remaining !== undefined"> · {{ device.resident_credentials_remaining }} resident slots</template></small>
        </span>
        <span v-if="backend === 'fido2' && devicePath === device.path" class="choice-check">✓</span>
      </button>

      <div v-if="!yubikeyConnected" class="storage-choice unavailable storage-unavailable">
        <span class="provider-icon"><AppIcon name="device" /></span>
        <span><strong>FIDO2 security key</strong><small>Connect a security key to use this storage</small></span>
        <span class="choice-status">Not connected</span>
      </div>

      <div v-if="backend === 'fido2'" class="new-key-options">
        <label class="new-key-algorithm"><span>Algorithm</span><select v-model="fidoAlgorithm"><option v-for="item in availableAlgorithms" :key="item" :value="item">{{ item }}</option></select></label>
      </div>

      <dl class="new-key-summary">
        <div><dt>Algorithm</dt><dd>{{ algorithm }}</dd></div>
        <div><dt>Available through</dt><dd>Keynoxis SSH Agent</dd></div>
      </dl>

      <p v-if="error" class="new-key-error">{{ error }}</p>

      <div class="new-key-actions">
        <button type="button" class="button quiet" :disabled="busy" @click="emit('close')">Cancel</button>
        <button type="submit" class="button primary" :disabled="busy || !name.trim() || (backend === 'fido2' && !devicePath)">
          {{ busy ? "Preparing…" : (backend === "fido2" ? "Continue" : "Create Key") }}
        </button>
      </div>
    </form>
  </div>
</template>
