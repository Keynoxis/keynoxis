// SPDX-License-Identifier: MPL-2.0

export type Phase =
  | "waiting_for_device"
  | "needs_pin"
  | "loading"
  | "waiting_for_touch"
  | "ready"
  | "error";

export interface SshKey {
  algorithm: string;
  public_key: string;
  fingerprint: string;
  comment?: string;
  backend: "fido2" | "secure_enclave" | "tpm";
  enabled: boolean;
  device_path?: string;
}

export interface DeviceInfo {
  label?: string;
  serial_number?: number;
  local_id?: number;
  product?: string;
  manufacturer?: string;
  path: string;
  vendor_id: number;
  product_id: number;
  fido2: boolean;
  credential_management: boolean;
  pin_configured: boolean;
  algorithms: string[];
  aaguid?: string;
  firmware?: string;
  resident_credentials_remaining?: number;
  pin_retries?: number;
}

export interface AppState {
  phase: Phase;
  yubikey_connected: boolean;
  agent_running: boolean;
  agent_locked: boolean;
  ssh_socket?: string;
  keys: SshKey[];
  device?: DeviceInfo;
  devices: DeviceInfo[];
  error?: string;
  pending_key_creation?: string;
  pending_key_algorithm?: string;
  pending_key_deletion?: string;
  pending_key_rename?: { fingerprint: string; name: string };
  fido_session_unlocked: boolean;
  unlocked_device_paths: string[];
  unlock_sequence: boolean;
  security_notice?: string;
}

export interface Settings {
  launch_at_login: boolean;
  launch_at_login_requires_approval: boolean;
  auto_lock_minutes: number;
  preferred_backend: "secure_enclave" | "fido2";
  pin: PinSettings;
  touch_id: TouchIdSettings;
}

export interface PinSettings {
  prompt_on_startup: boolean;
  prompt_on_device_connection: boolean;
  prompt_after_mac_unlock: boolean;
  require_for_create: boolean;
  require_for_rename: boolean;
  require_for_delete: boolean;
}

export interface TouchIdSettings {
  require_for_create: boolean;
  require_for_rename: boolean;
}

export interface ActivityEntry {
  id: number;
  timestamp_ms: number;
  category: "agent" | "device" | "key" | "signing";
  status: "info" | "success" | "warning" | "error";
  title: string;
  detail?: string;
}
