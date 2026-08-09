<!-- SPDX-License-Identifier: MPL-2.0 -->

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { ActivityEntry, AppState, DeviceInfo, Settings, SshKey } from "./types";
import AppIcon from "./components/AppIcon.vue";
import AppSidebar from "./components/AppSidebar.vue";
import AuthDialog from "./components/AuthDialog.vue";
import KeyDetails from "./components/KeyDetails.vue";
import KeyRow from "./components/KeyRow.vue";
import NewKeyDialog from "./components/NewKeyDialog.vue";
import SectionHeader from "./components/SectionHeader.vue";
import StatusDot from "./components/StatusDot.vue";

type Screen = "agent" | "keys" | "devices" | "activity" | "settings";

const state = ref<AppState>({ phase: "waiting_for_device", yubikey_connected: false, agent_running: false, agent_locked: false, keys: [], devices: [], fido_session_unlocked: false, unlocked_device_paths: [], unlock_sequence: false });
const settings = ref<Settings>({
  launch_at_login: false,
  launch_at_login_requires_approval: false,
  auto_lock_minutes: 15,
  preferred_backend: "secure_enclave",
  pin: {
    prompt_on_startup: false,
    prompt_on_device_connection: true,
    prompt_after_mac_unlock: true,
    require_for_create: true,
    require_for_rename: true,
    require_for_delete: true,
  },
  touch_id: {
    require_for_create: true,
    require_for_rename: true,
  },
});
const settingsBusy = ref(false);
const settingsError = ref<string>();
const appContent = ref<HTMLElement>();
const appWindow = getCurrentWindow();
const isAuthWindow = appWindow.label === "auth";
const screen = ref<Screen>("agent");
const selectedFingerprint = ref<string>();
const pin = ref("");
const unlocking = ref(false);
const copied = ref<string>();
const renameBusy = ref(false);
const renameError = ref<string>();
const removeBusy = ref(false);
const removeError = ref<string>();
const newKeyOpen = ref(false);
const newKeyBusy = ref(false);
const newKeyError = ref<string>();
const pendingCreatedName = ref<string>();
const keyDetails = ref<InstanceType<typeof KeyDetails>>();
const activity = ref<ActivityEntry[]>([]);
const activityFilter = ref<"all" | ActivityEntry["category"]>("all");
const editingDevicePath = ref<string>();
const deviceLabel = ref("");
const deviceLabelBusy = ref(false);
const deviceLabelError = ref<string>();
let unlistenState: UnlistenFn | undefined;
let unlistenNavigate: UnlistenFn | undefined;
let unlistenClose: UnlistenFn | undefined;
let unlistenActivity: UnlistenFn | undefined;

const selectedKey = computed(() => state.value.keys.find(key => key.fingerprint === selectedFingerprint.value));
const keyNameCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
function keysByName(backend: SshKey["backend"]) {
  return state.value.keys
    .filter(key => key.backend === backend)
    .sort((left, right) => {
      if (!left.comment) return right.comment ? 1 : 0;
      if (!right.comment) return -1;
      return keyNameCollator.compare(left.comment, right.comment);
    });
}
const secureEnclaveKeys = computed(() => keysByName("secure_enclave"));
const fidoKeys = computed(() => keysByName("fido2"));
const enabledKeys = computed(() => state.value.keys.filter(key => key.enabled));
const disabledKeys = computed(() => state.value.keys.filter(key => !key.enabled));
const activeIdentityCount = computed(() => state.value.agent_running && !state.value.agent_locked ? enabledKeys.value.length : 0);
const activeSecureEnclaveCount = computed(() => enabledKeys.value.filter(key => key.backend === "secure_enclave").length);
const activeFidoCount = computed(() => enabledKeys.value.filter(key => key.backend === "fido2").length);
const agentVisualState = computed(() => state.value.agent_locked ? "locked" : state.value.agent_running ? "running" : "stopped");
const agentStatusTitle = computed(() => state.value.agent_locked ? "SSH Agent Locked" : state.value.agent_running ? "SSH Agent Running" : "SSH Agent Unavailable");
const connectedSecurityKeys = computed(() => state.value.devices?.length ? state.value.devices : (state.value.device ? [state.value.device] : []));
const authDevicePosition = computed(() => Math.max(0, connectedSecurityKeys.value.findIndex(device => device.path === state.value.device?.path)) + 1);
const secureEnclavePriority = computed(() => settings.value.preferred_backend === "secure_enclave" ? 1 : 2);
const fidoPriority = computed(() => settings.value.preferred_backend === "fido2" ? 1 : 2);
const filteredActivity = computed(() => activityFilter.value === "all"
  ? activity.value
  : activity.value.filter(entry => entry.category === activityFilter.value));
const pinRelatedError = computed(() => /pin|attempt|blocked/i.test(state.value.error || ""));
const touchTimedOut = computed(() => state.value.error?.startsWith("Touch timed out.") === true);
const authMode = computed<"pin" | "unlocking" | "touch" | "error" | "disconnected" | undefined>(() => {
  if (state.value.phase === "waiting_for_touch") return "touch";
  if (unlocking.value) return "unlocking";
  if (state.value.phase === "needs_pin" || (state.value.phase === "error" && state.value.yubikey_connected && pinRelatedError.value)) return "pin";
  if (state.value.phase === "error") return "error";
  if (state.value.phase === "waiting_for_device" && isAuthWindow) return "disconnected";
  return undefined;
});
function deviceKeys(path: string) {
  return fidoKeys.value.filter(key => key.device_path === path);
}
function deviceConnectionState(device: DeviceInfo) {
  const active = state.value.device?.path === device.path;
  if (active && state.value.phase === "needs_pin") return { label: "PIN required", status: "warning" as const };
  if (active && state.value.phase === "waiting_for_touch") return { label: "Touch required", status: "warning" as const };
  if (state.value.unlocked_device_paths.includes(device.path)) return { label: "Unlocked", status: "success" as const };
  return { label: "Locked", status: "neutral" as const };
}
function keyDeviceName(key: SshKey) {
  return deviceName(connectedSecurityKeys.value.find(device => device.path === key.device_path));
}

watch(() => state.value.keys, keys => {
  if (!keys.some(key => key.fingerprint === selectedFingerprint.value)) selectedFingerprint.value = keys[0]?.fingerprint;
  if (pendingCreatedName.value) {
    const created = keys.find(key => key.backend === "fido2" && key.comment === pendingCreatedName.value);
    if (created) {
      selectedFingerprint.value = created.fingerprint;
      pendingCreatedName.value = undefined;
    }
  }
}, { immediate: true, deep: true });

async function refresh() {
  state.value = await invoke<AppState>("get_state");
}

async function unlock() {
  if (!pin.value || unlocking.value) return;
  unlocking.value = true;
  renameError.value = undefined;
  try {
    state.value = await invoke<AppState>("load_keys", { pin: pin.value });
  } catch {
    await refresh().catch(() => undefined);
  } finally {
    pin.value = "";
    unlocking.value = false;
  }
}

async function cancelAuth() {
  pin.value = "";
  try {
    state.value = await invoke<AppState>("dismiss_auth");
  } catch {
    await appWindow.hide();
  }
}

function handleEscape(event: KeyboardEvent) {
  if (isAuthWindow && authMode.value && event.key === "Escape") {
    event.preventDefault();
    cancelAuth();
  } else if (!isAuthWindow && newKeyOpen.value && event.key === "Escape") {
    event.preventDefault();
    closeNewKey();
  }
}

function closeNewKey() {
  if (newKeyBusy.value) return;
  newKeyOpen.value = false;
  newKeyError.value = undefined;
}

async function createKey(name: string, backend: "secure_enclave" | "fido2", algorithm: string, devicePath?: string) {
  if (newKeyBusy.value) return;
  newKeyBusy.value = true;
  newKeyError.value = undefined;
  try {
    if (backend === "fido2") {
      pendingCreatedName.value = name;
      state.value = await invoke<AppState>("request_fido_key_creation", { name, algorithm, devicePath });
      newKeyOpen.value = false;
      if (state.value.phase === "waiting_for_touch") {
        state.value = await invoke<AppState>("continue_fido_operation");
      }
    } else {
      state.value = await invoke<AppState>("create_secure_enclave_key", { name });
      const created = state.value.keys.find(key => key.backend === "secure_enclave" && key.comment === name);
      selectedFingerprint.value = created?.fingerprint;
    }
    newKeyOpen.value = false;
  } catch (error) {
    newKeyError.value = String(error);
  } finally {
    newKeyBusy.value = false;
  }
}

function deviceName(device?: DeviceInfo) {
  const base = device?.label || device?.product || "FIDO2 security key";
  if (!device || connectedSecurityKeys.value.length < 2) return base;
  const index = connectedSecurityKeys.value.findIndex(item => item.path === device.path);
  return index >= 0 ? `${base} · #${index + 1}` : base;
}

function editDeviceName(device: DeviceInfo) {
  editingDevicePath.value = device.path;
  deviceLabel.value = device.label || "";
  deviceLabelError.value = undefined;
}

async function saveDeviceName(device: DeviceInfo) {
  if (deviceLabelBusy.value) return;
  deviceLabelBusy.value = true;
  deviceLabelError.value = undefined;
  try {
    state.value = await invoke<AppState>("set_security_key_label", {
      path: device.path,
      label: deviceLabel.value,
    });
    editingDevicePath.value = undefined;
  } catch (error) {
    deviceLabelError.value = String(error);
  } finally {
    deviceLabelBusy.value = false;
  }
}

async function unlockDevice(path: string) {
  pin.value = "";
  try {
    state.value = await invoke<AppState>("request_device_unlock", { path });
  } catch (error) {
    settingsError.value = String(error);
  }
}

async function copyValue(value: string, kind: string) {
  await navigator.clipboard.writeText(value);
  copied.value = kind;
  window.setTimeout(() => { copied.value = undefined; }, 1500);
}

async function clearActivity() {
  activity.value = await invoke<ActivityEntry[]>("clear_activity");
}

async function toggleLaunchAtLogin() {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    settings.value = await invoke<Settings>("set_launch_at_login", { enabled: !settings.value.launch_at_login });
  } catch (error) {
    settingsError.value = String(error);
  } finally {
    settingsBusy.value = false;
  }
}

async function changeAutoLock(event: Event) {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    const minutes = Number((event.target as HTMLSelectElement).value);
    settings.value = await invoke<Settings>("set_auto_lock_timeout", { minutes });
  } catch (error) {
    settingsError.value = String(error);
    settings.value = await invoke<Settings>("get_settings");
  } finally {
    settingsBusy.value = false;
  }
}

async function changePreferredBackend(event: Event) {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    const preferredBackend = (event.target as HTMLSelectElement).value as Settings["preferred_backend"];
    settings.value = await invoke<Settings>("set_preferred_backend", { preferredBackend });
  } catch (error) {
    settingsError.value = String(error);
    settings.value = await invoke<Settings>("get_settings");
  } finally {
    settingsBusy.value = false;
  }
}

async function togglePinSetting(key: keyof Settings["pin"]) {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    const pinSettings = { ...settings.value.pin, [key]: !settings.value.pin[key] };
    settings.value = await invoke<Settings>("set_pin_settings", { pinSettings });
  } catch (error) {
    settingsError.value = String(error);
    settings.value = await invoke<Settings>("get_settings");
  } finally {
    settingsBusy.value = false;
  }
}

async function toggleTouchIdSetting(key: keyof Settings["touch_id"]) {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    const touchIdSettings = { ...settings.value.touch_id, [key]: !settings.value.touch_id[key] };
    settings.value = await invoke<Settings>("set_touch_id_settings", { touchIdSettings });
  } catch (error) {
    settingsError.value = String(error);
    settings.value = await invoke<Settings>("get_settings");
  } finally {
    settingsBusy.value = false;
  }
}

async function lockAgentNow() {
  if (settingsBusy.value) return;
  settingsBusy.value = true;
  settingsError.value = undefined;
  try {
    state.value = await invoke<AppState>(state.value.agent_locked ? "unlock_agent" : "lock_agent");
  } catch (error) {
    settingsError.value = String(error);
  } finally {
    settingsBusy.value = false;
  }
}

function activityTime(timestamp: number) {
  const date = new Date(timestamp);
  const today = new Date();
  const sameDay = date.getFullYear() === today.getFullYear()
    && date.getMonth() === today.getMonth()
    && date.getDate() === today.getDate();
  return sameDay
    ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function activityIcon(category: ActivityEntry["category"]) {
  if (category === "device") return "device";
  if (category === "key") return "key";
  if (category === "signing") return "shield";
  return "activity";
}

async function renameKey(key: SshKey, name: string) {
  if (renameBusy.value) return;
  renameBusy.value = true;
  renameError.value = undefined;
  try {
    state.value = await invoke<AppState>("rename_key", { fingerprint: key.fingerprint, name });
  } catch (error) {
    renameError.value = String(error);
  } finally {
    renameBusy.value = false;
  }
}

async function deleteKey(key: SshKey) {
  if (removeBusy.value) return;
  removeBusy.value = true;
  removeError.value = undefined;
  try {
    if (key.backend === "fido2") {
      state.value = await invoke<AppState>("request_fido_key_deletion", { fingerprint: key.fingerprint });
      keyDetails.value?.closeRemove();
      if (state.value.phase === "waiting_for_touch") {
        state.value = await invoke<AppState>("continue_fido_operation");
      }
    } else {
      state.value = await invoke<AppState>("delete_key", { fingerprint: key.fingerprint });
    }
  } catch (error) {
    removeError.value = String(error);
  } finally {
    removeBusy.value = false;
  }
}

async function toggleKeyEnabled(key: SshKey) {
  try {
    state.value = await invoke<AppState>("set_key_enabled", {
      fingerprint: key.fingerprint,
      enabled: !key.enabled,
    });
  } catch (error) {
    settingsError.value = String(error);
  }
}

function navigate(value: string) {
  if (!["agent", "keys", "devices", "activity", "settings"].includes(value)) return;
  screen.value = value as Screen;
  nextTick(() => appContent.value?.scrollTo({ top: 0 }));
}

onMounted(async () => {
  await refresh();
  if (!isAuthWindow) {
    activity.value = await invoke<ActivityEntry[]>("get_activity");
    try {
      settings.value = await invoke<Settings>("get_settings");
    } catch (error) {
      settingsError.value = String(error);
    }
  }
  unlistenState = await listen<AppState>("state-changed", ({ payload }) => { state.value = payload; });
  if (!isAuthWindow) {
    unlistenActivity = await listen<ActivityEntry>("activity-added", ({ payload }) => {
      activity.value = [payload, ...activity.value.filter(entry => entry.id !== payload.id)].slice(0, 2000);
    });
  }
  unlistenNavigate = await listen<string>("navigate", ({ payload }) => navigate(payload));
  unlistenClose = await appWindow.onCloseRequested(() => { cancelAuth(); });
  window.addEventListener("keydown", handleEscape);
});

onBeforeUnmount(() => {
  pin.value = "";
  window.removeEventListener("keydown", handleEscape);
  unlistenState?.();
  unlistenNavigate?.();
  unlistenClose?.();
  unlistenActivity?.();
});
</script>

<template>
  <main v-if="isAuthWindow" class="auth-window-shell" data-tauri-drag-region>
    <AuthDialog
      v-if="authMode"
      v-model="pin"
      :mode="authMode"
      :device="state.device"
      :device-position="authDevicePosition"
      :device-count="connectedSecurityKeys.length"
      :sequential="state.unlock_sequence"
      :busy="unlocking"
      :error="state.error"
      :timeout="touchTimedOut"
      :creating-key="Boolean(state.pending_key_creation)"
      :deleting-key="Boolean(state.pending_key_deletion)"
      :renaming-key="Boolean(state.pending_key_rename)"
      windowed
      @unlock="unlock"
    />
  </main>

  <main v-else class="app-shell">
    <AppSidebar :active="screen" :agent-running="state.agent_running && !state.agent_locked" :identities="state.agent_locked ? 0 : state.keys.filter(key => key.enabled).length" @navigate="navigate" />

    <section ref="appContent" class="app-content" :class="{ 'keys-screen': screen === 'keys' }">
      <template v-if="screen === 'agent'">
        <div class="agent-page">
          <div v-if="settingsError" class="settings-error agent-error"><StatusDot status="danger" />{{ settingsError }}</div>

          <section class="agent-hero" :class="agentVisualState">
            <div class="agent-emblem" aria-hidden="true">
              <span class="agent-emblem-ring ring-one"></span>
              <span class="agent-emblem-ring ring-two"></span>
              <span class="agent-emblem-core"><AppIcon name="activity" :size="39" /></span>
            </div>
            <p class="agent-eyebrow">Keynoxis SSH Agent</p>
            <h1>{{ agentStatusTitle }}</h1>
            <p class="agent-hero-copy">{{ state.agent_locked ? "Identities are hidden and cached FIDO2 PINs have been cleared." : state.agent_running ? "Hardware-backed identities are available to SSH, Git and your development tools." : "The local OpenSSH-compatible agent is not responding." }}</p>
            <div class="agent-count" :class="agentVisualState">
              <strong>{{ activeIdentityCount }}</strong>
              <span>active {{ activeIdentityCount === 1 ? "identity" : "identities" }}</span>
            </div>
            <div class="agent-hero-actions">
              <button class="button primary agent-control" :disabled="settingsBusy || !state.agent_running" @click="lockAgentNow">
                <AppIcon :name="state.agent_locked ? 'key' : 'shield'" :size="15" />
                {{ state.agent_locked ? "Unlock Agent" : "Lock Agent" }}
              </button>
              <button class="button secondary" @click="navigate('keys')"><AppIcon name="key" :size="15" />Manage Keys</button>
            </div>
          </section>

          <div class="agent-dashboard">
            <section class="agent-card identities-card">
              <header><span class="agent-card-icon"><AppIcon name="key" :size="16" /></span><div><h2>Identity availability</h2><p>Keys currently presented to SSH clients.</p></div></header>
              <div class="agent-metrics">
                <div><strong>{{ activeIdentityCount }}</strong><span>Active</span></div>
                <div><strong>{{ disabledKeys.length }}</strong><span>Disabled</span></div>
                <div><strong>{{ state.keys.length }}</strong><span>Total</span></div>
              </div>
              <div class="agent-provider-row"><span><AppIcon name="chip" :size="14" />Secure Enclave</span><strong>{{ activeSecureEnclaveCount }} enabled</strong></div>
              <div class="agent-provider-row"><span><AppIcon name="device" :size="14" />Security keys</span><strong>{{ activeFidoCount }} enabled</strong></div>
              <div v-if="enabledKeys.length" class="agent-key-chips">
                <span v-for="key in enabledKeys.slice(0, 4)" :key="key.fingerprint">{{ key.comment || "Unnamed identity" }}</span>
                <span v-if="enabledKeys.length > 4">+{{ enabledKeys.length - 4 }}</span>
              </div>
              <p v-else class="agent-card-empty">No enabled SSH identities.</p>
            </section>

            <section class="agent-card integration-card">
              <header><span class="agent-card-icon"><AppIcon name="activity" :size="16" /></span><div><h2>OpenSSH integration</h2><p>One stable socket for every compatible client.</p></div></header>
              <div class="agent-integration-status"><StatusDot :status="state.agent_running ? 'success' : 'danger'" /><strong>{{ state.agent_running ? "Ready" : "Unavailable" }}</strong><span class="agent-client-list">SSH · Git · SCP · rsync · IDE</span></div>
              <div class="agent-socket">
                <span>Agent socket</span>
                <code>{{ state.ssh_socket || "Unavailable" }}</code>
                <button v-if="state.ssh_socket" class="icon-button" title="Copy socket" @click="copyValue(state.ssh_socket, 'socket')"><AppIcon name="copy" /></button>
              </div>
            </section>

            <section class="agent-card protection-card">
              <header><span class="agent-card-icon protected"><AppIcon name="shield" :size="16" /></span><div><h2>Protection</h2><p>Security controls enforced by the agent.</p></div></header>
              <div class="agent-protection-row"><span><AppIcon name="shield" :size="14" /><span><strong>Agent forwarding</strong><small>Forwarded signing requests are rejected</small></span></span><em>Blocked</em></div>
              <div class="agent-protection-row"><span><AppIcon name="activity" :size="14" /><span><strong>Automatic lock</strong><small>{{ settings.auto_lock_minutes ? `${settings.auto_lock_minutes} minutes of inactivity` : "Disabled in Settings" }}</small></span></span><em>{{ settings.auto_lock_minutes ? "Active" : "Off" }}</em></div>
              <div class="agent-protection-row"><span><AppIcon name="chip" :size="14" /><span><strong>macOS lock and sleep</strong><small>FIDO2 PINs are wiped automatically</small></span></span><em>Always on</em></div>
            </section>
          </div>
        </div>
      </template>

      <template v-else-if="screen === 'keys'">
        <SectionHeader title="Keys" description="Hardware-backed SSH identities available to your agent.">
          <button class="button secondary" @click="newKeyOpen = true"><AppIcon name="plus" :size="15" />New Key</button>
        </SectionHeader>

        <div v-if="state.phase === 'error' && !pinRelatedError" class="error-banner">
          <StatusDot status="danger" />
          <span>{{ state.error }}</span>
        </div>
        <div v-if="state.security_notice" class="warning-banner">
          <StatusDot status="warning" />
          <span>{{ state.security_notice }}</span>
        </div>

        <div class="keys-layout">
          <section class="key-list-pane">
            <div class="key-group">
              <div class="group-heading">
                <div class="provider-heading-label">
                  <p class="section-label">This Mac</p>
                  <span v-if="secureEnclavePriority === 1" class="priority-badge primary">Priority</span>
                </div>
              </div>
              <div class="device-group-title local-provider-title">
                <span><StatusDot status="success" />Secure Enclave</span>
                <small>{{ secureEnclaveKeys.length }} {{ secureEnclaveKeys.length === 1 ? "key" : "keys" }}</small>
              </div>
              <div v-if="secureEnclaveKeys.length" class="key-list">
                <KeyRow
                  v-for="key in secureEnclaveKeys"
                  :key="key.fingerprint"
                  :key-item="key"
                  :selected="selectedFingerprint === key.fingerprint"
                  :available="true"
                  @select="selectedFingerprint = key.fingerprint"
                />
              </div>
              <div v-else class="empty-state compact local-empty">
                <span class="provider-icon"><AppIcon name="chip" /></span>
                <div><strong>No local SSH keys</strong><p>Create a hardware-backed key in Secure Enclave.</p></div>
              </div>
            </div>

            <div class="key-group security-keys-group">
              <div class="group-heading">
                <div class="provider-heading-label">
                  <p class="section-label">Security Keys</p>
                  <span v-if="fidoPriority === 1" class="priority-badge primary">Priority</span>
                </div>
              </div>
              <div v-for="device in connectedSecurityKeys" :key="device.path" class="security-device-keys">
                <div class="device-group-title">
                  <span><StatusDot :status="deviceConnectionState(device).status" />{{ deviceName(device) }}</span>
                  <span class="device-key-actions">
                    <small>{{ deviceKeys(device.path).length }} {{ deviceKeys(device.path).length === 1 ? "key" : "keys" }}</small>
                    <button class="text-button" @click="unlockDevice(device.path)">{{ state.unlocked_device_paths.includes(device.path) ? "Reload" : "Unlock" }}</button>
                  </span>
                </div>
                <div v-if="deviceKeys(device.path).length" class="key-list">
                  <KeyRow
                    v-for="key in deviceKeys(device.path)"
                    :key="key.fingerprint"
                    :key-item="key"
                    :selected="selectedFingerprint === key.fingerprint"
                    :available="true"
                    @select="selectedFingerprint = key.fingerprint"
                  />
                </div>
              </div>
              <div v-if="!fidoKeys.length" class="empty-state">
                <AppIcon name="device" :size="22" />
                <strong>{{ state.yubikey_connected ? "No resident SSH identities" : "No security key connected" }}</strong>
                <p>{{ state.yubikey_connected ? (state.fido_session_unlocked ? "Create a resident SSH key to use this security key." : "Unlock the security key to load its FIDO2 identities.") : "Insert a FIDO2 security key to make its SSH identities available." }}</p>
              </div>
            </div>
          </section>

          <KeyDetails
            v-if="selectedKey"
            ref="keyDetails"
            :key="selectedKey.fingerprint"
            :key-item="selectedKey"
            :available="true"
            :device-name="selectedKey.backend === 'secure_enclave' ? 'Secure Enclave' : keyDeviceName(selectedKey)"
            :busy="renameBusy"
            :error="renameError"
            :removing="removeBusy"
            :remove-error="removeError"
            @copy="copyValue"
            @rename="name => renameKey(selectedKey!, name)"
            @remove="deleteKey(selectedKey!)"
            @toggle-enabled="toggleKeyEnabled(selectedKey!)"
          />
          <aside v-else class="details-placeholder">
            <AppIcon name="key" :size="23" />
            <p>Select an identity to view its details.</p>
          </aside>
        </div>
      </template>

      <template v-else-if="screen === 'devices'">
        <SectionHeader title="Devices" description="Hardware storage available to Keynoxis." />
        <div class="single-column-content">
          <section class="content-group">
            <p class="section-label">This Mac</p>
            <div class="device-row">
              <span class="device-row-icon"><AppIcon name="chip" /></span>
              <div><strong>Secure Enclave</strong><p>Apple Silicon hardware-backed key storage</p></div>
              <span class="device-status"><StatusDot status="success" />Available · {{ secureEnclaveKeys.length }} {{ secureEnclaveKeys.length === 1 ? "identity" : "identities" }}</span>
            </div>
          </section>
          <section class="content-group">
            <p class="section-label">Security Keys</p>
            <div v-if="deviceLabelError" class="settings-error"><StatusDot status="danger" />{{ deviceLabelError }}</div>
            <div v-for="device in connectedSecurityKeys" :key="device.path" class="device-row">
              <span class="device-row-icon"><AppIcon name="device" /></span>
              <div>
                <form v-if="editingDevicePath === device.path" class="device-name-editor" @click.stop @submit.prevent="saveDeviceName(device)">
                  <input v-model="deviceLabel" maxlength="64" placeholder="e.g. Main or Backup" autofocus @keyup.esc="editingDevicePath = undefined" />
                  <button class="button primary small" :disabled="deviceLabelBusy">Save</button>
                  <button type="button" class="button quiet small" :disabled="deviceLabelBusy" @click="editingDevicePath = undefined">Cancel</button>
                </form>
                <template v-else>
                  <div class="device-name-line"><strong>{{ deviceName(device) }}</strong><button class="text-button" @click.stop="editDeviceName(device)">{{ device.label ? "Rename" : "Name" }}</button></div>
                  <p>{{ device.label ? `${device.product || "FIDO2 security key"} · ` : "" }}USB · {{ device.fido2 ? "FIDO2" : "Unsupported" }} · {{ device.algorithms.join(" / ") || "Algorithms unavailable" }}</p>
                </template>
                <dl class="device-facts">
                  <div><dt>Firmware</dt><dd>{{ device.firmware || "Unknown" }}</dd></div>
                  <div v-if="device.serial_number"><dt>Serial</dt><dd>{{ device.serial_number }}</dd></div>
                  <div><dt>PIN</dt><dd>{{ device.pin_configured ? `${device.pin_retries ?? "?"} retries` : "Not configured" }}</dd></div>
                  <div><dt>Resident slots</dt><dd>{{ device.resident_credentials_remaining ?? "Unknown" }}</dd></div>
                  <div><dt>AAGUID</dt><dd>{{ device.aaguid || "Unavailable" }}</dd></div>
                </dl>
              </div>
              <span class="device-status"><StatusDot :status="deviceConnectionState(device).status" />{{ deviceConnectionState(device).label }}</span>
            </div>
            <div v-if="!connectedSecurityKeys.length" class="empty-state compact"><AppIcon name="device" /><div><strong>No security key connected</strong><p>Insert a FIDO2 security key to continue.</p></div></div>
          </section>
        </div>
      </template>

      <template v-else-if="screen === 'activity'">
        <SectionHeader title="Activity" description="Persistent local SSH-agent and hardware activity.">
          <button class="button secondary" :disabled="!activity.length" @click="clearActivity">Clear</button>
        </SectionHeader>
        <div class="activity-content">
          <div class="activity-toolbar">
            <div class="activity-filters" aria-label="Activity filters">
              <button v-for="filter in (['all', 'signing', 'key', 'device', 'agent'] as const)" :key="filter" :class="{ active: activityFilter === filter }" @click="activityFilter = filter">
                {{ filter === "all" ? "All" : filter === "key" ? "Keys" : filter.charAt(0).toUpperCase() + filter.slice(1) }}
              </button>
            </div>
            <span>{{ filteredActivity.length }} {{ filteredActivity.length === 1 ? "event" : "events" }}</span>
          </div>

          <div v-if="!filteredActivity.length" class="activity-empty">
            <AppIcon name="activity" :size="24" />
            <strong>{{ activity.length ? "No matching activity" : "No activity yet" }}</strong>
            <p>Device, key and SSH signing events will appear here.</p>
          </div>

          <ol v-else class="activity-list">
            <li v-for="entry in filteredActivity" :key="entry.id" class="activity-row">
              <span class="activity-icon" :class="entry.status"><AppIcon :name="activityIcon(entry.category)" :size="16" /></span>
              <div class="activity-copy"><strong>{{ entry.title }}</strong><p v-if="entry.detail">{{ entry.detail }}</p></div>
              <div class="activity-meta"><time :datetime="new Date(entry.timestamp_ms).toISOString()">{{ activityTime(entry.timestamp_ms) }}</time><span :class="entry.status"><StatusDot :status="entry.status === 'error' ? 'danger' : entry.status === 'warning' ? 'warning' : entry.status === 'success' ? 'success' : 'neutral'" />{{ entry.status }}</span></div>
            </li>
          </ol>
        </div>
      </template>

      <template v-else>
        <SectionHeader title="Settings" description="Security and authentication preferences." />
        <div class="settings-content">
          <div v-if="settingsError" class="settings-error"><StatusDot status="danger" />{{ settingsError }}</div>

          <section class="settings-group">
            <header class="settings-group-header"><span class="settings-group-icon"><AppIcon name="settings" :size="16" /></span><div><h2>Startup and SSH</h2><p>How Keynoxis starts and presents identities to OpenSSH.</p></div></header>
            <div class="settings-card">
              <div class="settings-row"><div><strong>Launch at login</strong><p>{{ settings.launch_at_login_requires_approval ? "Approval required in System Settings → Login Items." : "Start the agent when you sign in to this Mac." }}</p></div><button class="switch-control" :class="{ on: settings.launch_at_login }" role="switch" :aria-checked="settings.launch_at_login" :disabled="settingsBusy" @click="toggleLaunchAtLogin"><span /></button></div>
              <div class="settings-row"><div><strong>Preferred key source</strong><p>Choose which hardware-backed identities OpenSSH tries first.</p></div><select class="settings-select provider-priority-select" :value="settings.preferred_backend" :disabled="settingsBusy" @change="changePreferredBackend"><option value="secure_enclave">This Mac first</option><option value="fido2">Security key first</option></select></div>
              <div class="settings-enforced single-column">
                <div><AppIcon name="shield" :size="15" /><span><strong>Agent forwarding protection</strong><small>Forwarded SSH signature requests are rejected and recorded in Activity</small></span><em>Enforced</em></div>
              </div>
            </div>
          </section>

          <section class="settings-group">
            <header class="settings-group-header"><span class="settings-group-icon"><AppIcon name="device" :size="16" /></span><div><h2>Security key PIN</h2><p>Control when a FIDO2 key asks for its PIN.</p></div></header>
            <div class="settings-card">
              <div class="settings-group-note"><AppIcon name="shield" :size="13" /><span>Enabling protection is immediate. Disabling it requires Touch ID.</span></div>
              <p class="settings-subheading">Automatic prompts</p>
              <div class="settings-row"><div><strong>At application launch</strong><p>Ask when a security key is already connected.</p></div><button class="switch-control" :class="{ on: settings.pin.prompt_on_startup }" role="switch" :aria-checked="settings.pin.prompt_on_startup" :disabled="settingsBusy" @click="togglePinSetting('prompt_on_startup')"><span /></button></div>
              <div class="settings-row"><div><strong>When a security key is connected</strong><p>Open the PIN window as soon as a new FIDO2 key is detected.</p></div><button class="switch-control" :class="{ on: settings.pin.prompt_on_device_connection }" role="switch" :aria-checked="settings.pin.prompt_on_device_connection" :disabled="settingsBusy" @click="togglePinSetting('prompt_on_device_connection')"><span /></button></div>
              <div class="settings-row"><div><strong>After unlocking this Mac</strong><p>Open the PIN window when macOS becomes active again after lock or sleep.</p></div><button class="switch-control" :class="{ on: settings.pin.prompt_after_mac_unlock }" role="switch" :aria-checked="settings.pin.prompt_after_mac_unlock" :disabled="settingsBusy" @click="togglePinSetting('prompt_after_mac_unlock')"><span /></button></div>
              <p class="settings-subheading divided">Sensitive operations</p>
              <div class="settings-row"><div><strong>Create resident keys</strong><p>Require a fresh PIN even when the current session is unlocked.</p></div><button class="switch-control" :class="{ on: settings.pin.require_for_create }" role="switch" :aria-checked="settings.pin.require_for_create" :disabled="settingsBusy" @click="togglePinSetting('require_for_create')"><span /></button></div>
              <div class="settings-row"><div><strong>Rename resident keys</strong><p>Require a fresh PIN before changing a key name.</p></div><button class="switch-control" :class="{ on: settings.pin.require_for_rename }" role="switch" :aria-checked="settings.pin.require_for_rename" :disabled="settingsBusy" @click="togglePinSetting('require_for_rename')"><span /></button></div>
              <div class="settings-row"><div><strong>Remove resident keys</strong><p>Require a fresh PIN before permanent deletion. Physical touch is always required.</p></div><button class="switch-control" :class="{ on: settings.pin.require_for_delete }" role="switch" :aria-checked="settings.pin.require_for_delete" :disabled="settingsBusy" @click="togglePinSetting('require_for_delete')"><span /></button></div>
            </div>
          </section>

          <section class="settings-group">
            <header class="settings-group-header"><span class="settings-group-icon"><AppIcon name="fingerprint" :size="16" /></span><div><h2>Touch ID</h2><p>Biometric confirmation for keys stored in Secure Enclave.</p></div></header>
            <div class="settings-card">
              <div class="settings-group-note"><AppIcon name="shield" :size="13" /><span>Enabling protection is immediate. Disabling it requires Touch ID.</span></div>
              <div class="settings-row"><div><strong>Create Secure Enclave keys</strong><p>Confirm before provisioning a new SSH identity.</p></div><button class="switch-control" :class="{ on: settings.touch_id.require_for_create }" role="switch" :aria-checked="settings.touch_id.require_for_create" :disabled="settingsBusy" @click="toggleTouchIdSetting('require_for_create')"><span /></button></div>
              <div class="settings-row"><div><strong>Rename Secure Enclave keys</strong><p>Confirm before changing an identity name.</p></div><button class="switch-control" :class="{ on: settings.touch_id.require_for_rename }" role="switch" :aria-checked="settings.touch_id.require_for_rename" :disabled="settingsBusy" @click="toggleTouchIdSetting('require_for_rename')"><span /></button></div>
              <div class="settings-enforced">
                <div><AppIcon name="shield" :size="15" /><span><strong>SSH signatures</strong><small>Touch ID for every signature</small></span><em>Enforced</em></div>
                <div><AppIcon name="shield" :size="15" /><span><strong>Permanent deletion</strong><small>Touch ID before removing a key</small></span><em>Enforced</em></div>
              </div>
            </div>
          </section>

          <section class="settings-group">
            <header class="settings-group-header"><span class="settings-group-icon"><AppIcon name="shield" :size="16" /></span><div><h2>Session locking</h2><p>When Keynoxis forgets the cached FIDO2 PIN.</p></div></header>
            <div class="settings-card">
              <div class="settings-row"><div><strong>Automatic lock</strong><p>Clear the cached PIN after a period without FIDO2 activity.</p></div><select class="settings-select" :value="settings.auto_lock_minutes" :disabled="settingsBusy" @change="changeAutoLock"><option :value="5">5 minutes</option><option :value="15">15 minutes</option><option :value="30">30 minutes</option><option :value="60">1 hour</option><option :value="0">Never</option></select></div>
              <div class="settings-enforced single-column">
                <div><AppIcon name="shield" :size="15" /><span><strong>macOS lock and sleep</strong><small>PIN is wiped and FIDO2 identities are unloaded</small></span><em>Always on</em></div>
                <div><AppIcon name="activity" :size="15" /><span><strong>Wake recovery</strong><small>SSH Agent is verified and restored automatically</small></span><em>Automatic</em></div>
              </div>
            </div>
          </section>

        </div>
      </template>
    </section>

    <div v-if="copied" class="copy-feedback">Copied to clipboard</div>
    <NewKeyDialog
      :open="newKeyOpen"
      :busy="newKeyBusy"
      :error="newKeyError"
      :devices="connectedSecurityKeys"
      :active-device-path="state.device?.path"
      @close="closeNewKey"
      @create="createKey"
    />
  </main>
</template>
