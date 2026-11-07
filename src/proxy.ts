import { invoke } from "@tauri-apps/api/core";
import { PROXY_KIND_LABELS, type DefaultProxy } from "./types";

/**
 * This device's default proxy — see `src-tauri/src/proxy.rs`. It lives in
 * `proxy.json` and not in the workspace: whether a proxy is needed depends on
 * the network the machine is currently in.
 */
export function defaultProxy() {
  return invoke<DefaultProxy | null>("proxy_default_get");
}

/** `null` removes it. */
export function setDefaultProxy(proxy: DefaultProxy | null) {
  return invoke("proxy_default_set", { proxy });
}

export function proxyLabel(proxy: { kind: DefaultProxy["kind"]; host: string; port: number }) {
  const host = proxy.host.includes(":") ? `[${proxy.host}]` : proxy.host;
  return `${PROXY_KIND_LABELS[proxy.kind]} ${host}:${proxy.port}`;
}

/** The usual port per kind — 1080 for SOCKS, 3128 as with Squid. */
export const PROXY_PORTS = { socks5: 1080, http: 3128 } as const;
