// SPDX-License-Identifier: MPL-2.0

export const capabilities = {
  fido2: true,
  secureEnclave: true,
  activity: false,
  keyCreation: true,
  signatureApproval: false,
  launchAtLogin: false,
  automaticUpdates: false,
  lockOnMacLock: false
} as const;
