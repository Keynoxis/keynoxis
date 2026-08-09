<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import type { SshKey } from "../types";
import AppIcon from "./AppIcon.vue";
import StatusDot from "./StatusDot.vue";

const props = defineProps<{ keyItem: SshKey; deviceName?: string; busy?: boolean; error?: string; available: boolean; removing?: boolean; removeError?: string }>();
const emit = defineEmits<{ copy: [value: string, kind: string]; rename: [name: string]; remove: []; toggleEnabled: [] }>();
const editing = ref(false);
const name = ref("");
const input = ref<HTMLInputElement>();
const removeOpen = ref(false);
const removeConfirmation = ref("");
const removeInput = ref<HTMLInputElement>();
const removeAttempted = ref(false);
const algorithm = computed(() => props.keyItem.algorithm.replace("sk-", "").replace("@openssh.com", "").replace("ssh-", "").toUpperCase());
const protection = computed(() => props.keyItem.backend === "secure_enclave"
  ? { title: "Secure Enclave", detail: "Touch ID for every signature · Non-exportable" }
  : { title: "FIDO2", detail: "PIN · Physical touch" });

async function startRename() {
  name.value = props.keyItem.comment || "";
  editing.value = true;
  await nextTick();
  input.value?.focus();
}

function save() {
  const value = name.value.trim();
  if (value) emit("rename", value);
}

async function openRemove() {
  removeConfirmation.value = "";
  removeAttempted.value = false;
  removeOpen.value = true;
  await nextTick();
  removeInput.value?.focus();
}

function confirmRemove() {
  if (props.removing || removeConfirmation.value !== (props.keyItem.comment || "REMOVE")) return;
  removeAttempted.value = true;
  emit("remove");
}

function closeRemove() {
  if (props.removing) return;
  removeOpen.value = false;
  removeConfirmation.value = "";
}

defineExpose({ startRename, closeRemove });

watch(() => props.busy, (busy, wasBusy) => {
  if (wasBusy && !busy && !props.error) editing.value = false;
});
</script>

<template>
  <aside class="key-details">
    <div class="details-title-row" :class="{ editing }">
      <div v-if="editing" class="rename-field">
        <input ref="input" v-model="name" maxlength="64" @keyup.enter="save" @keyup.esc="editing = false" />
        <span v-if="error" class="inline-error">{{ error }}</span>
      </div>
      <div v-else>
        <p class="section-label">Key details</p>
        <h2>{{ keyItem.comment || "Resident key" }}</h2>
      </div>
      <div class="detail-title-actions">
        <template v-if="editing">
          <button class="button primary small" :disabled="busy || !name.trim()" @click="save">{{ busy ? "Saving…" : "Save" }}</button>
          <button class="button quiet small" :disabled="busy" @click="editing = false">Cancel</button>
        </template>
        <button v-else class="button quiet small" @click="startRename">Rename</button>
      </div>
    </div>

    <div class="detail-state" :class="{ locked: !available }"><StatusDot :status="available ? 'success' : 'warning'" />{{ available ? "Available to SSH agent" : "FIDO2 session locked" }}</div>

    <dl class="metadata-grid">
      <div><dt>Backend</dt><dd>{{ deviceName || (keyItem.backend === "fido2" ? "FIDO2 security key" : keyItem.backend) }}</dd></div>
      <div><dt>Algorithm</dt><dd>{{ algorithm }}</dd></div>
    </dl>

    <section class="details-section protection">
      <p class="section-label">Protection</p>
      <div><AppIcon name="shield" /><span><strong>{{ protection.title }}</strong><small>{{ protection.detail }}</small></span></div>
    </section>

    <section class="key-availability-setting">
      <div><strong>Available to SSH agent</strong><p>Disable this identity without removing it from hardware.</p></div>
      <button class="switch-control" :class="{ on: keyItem.enabled }" role="switch" :aria-checked="keyItem.enabled" @click="emit('toggleEnabled')"><span /></button>
    </section>

    <section class="details-section key-data-section">
      <div class="details-section-heading"><span>Fingerprint</span><button class="text-button" @click="emit('copy', keyItem.fingerprint, 'fingerprint')"><AppIcon name="copy" :size="13" />Copy</button></div>
      <code class="key-data-value fingerprint-value">{{ keyItem.fingerprint }}</code>
    </section>

    <section class="details-section key-data-section">
      <div class="details-section-heading"><span>Public key</span><button class="text-button" @click="emit('copy', keyItem.public_key, 'key')"><AppIcon name="copy" :size="13" />Copy</button></div>
      <code class="key-data-value public-key-value">{{ keyItem.public_key }}</code>
    </section>

    <section class="danger-zone">
      <div><strong>Remove key</strong><p>Remove this identity from its hardware storage.</p></div>
      <button class="button danger small" @click="openRemove">Remove</button>
    </section>

    <Teleport to="body">
      <div v-if="removeOpen" class="remove-key-backdrop" @click.self="closeRemove">
        <section class="remove-key-dialog" role="alertdialog" aria-modal="true" aria-labelledby="remove-key-title">
          <span class="remove-key-icon"><AppIcon name="key" :size="20" /></span>
          <h2 id="remove-key-title">Remove SSH key?</h2>
          <p>This permanently removes <strong>{{ keyItem.comment || "this identity" }}</strong> from {{ keyItem.backend === "fido2" ? "the security key" : "this Mac's Secure Enclave" }}.</p>
          <p class="remove-key-warning">Public keys already installed on servers are not removed automatically.</p>
          <div class="remove-confirm-field">
            <div class="remove-confirm-label">
              <span>Type</span>
              <button class="remove-key-name-copy" type="button" title="Copy key name" @click="emit('copy', keyItem.comment || 'REMOVE', 'name')">
                <strong>{{ keyItem.comment || "REMOVE" }}</strong><AppIcon name="copy" :size="12" />
              </button>
              <span>to confirm</span>
            </div>
            <input ref="removeInput" v-model="removeConfirmation" :aria-label="`Type ${keyItem.comment || 'REMOVE'} to confirm deletion`" :disabled="removing" autocomplete="off" spellcheck="false" @keyup.enter="confirmRemove" @keyup.esc="closeRemove" />
          </div>
          <p v-if="removeAttempted && removeError" class="remove-key-error">{{ removeError }}</p>
          <div class="remove-key-actions">
            <button class="button quiet small" :disabled="removing" @click="closeRemove">Cancel</button>
            <button class="button danger small" :disabled="removing || removeConfirmation !== (keyItem.comment || 'REMOVE')" @click="confirmRemove">{{ removing ? "Removing…" : "Remove key" }}</button>
          </div>
          <small>{{ keyItem.backend === "secure_enclave" ? "Touch ID will be required." : "A fresh FIDO2 PIN and physical touch will be required." }}</small>
        </section>
      </div>
    </Teleport>
  </aside>
</template>
