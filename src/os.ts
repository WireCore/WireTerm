/**
 * os-release `ID` to a brand mark.
 *
 * The logos come from simple-icons rather than being drawn here, so they are
 * the real ones and stay right as the distributions redesign them.
 *
 * `ID` is not unique across the world — distributions derived from another one
 * pick their own — so unknown ids fall back to `ID_LIKE` handling in
 * [`osIcon`] and finally to the Linux penguin.
 *
 * Two of the ids in here are not operating systems at all: an S3 endpoint has
 * no `/etc/os-release` to read, so what it reports is the implementation that
 * answered — see the backend's `read_system`. The same field, a different kind
 * of answer, and the card draws it the same way.
 */

import {
  siAlmalinux,
  siAlpinelinux,
  siApple,
  siArchlinux,
  siCentos,
  siCeph,
  siDebian,
  siFedora,
  siFreebsd,
  siGentoo,
  siHetzner,
  siKalilinux,
  siLinux,
  siLinuxmint,
  siManjaro,
  siMinio,
  siNixos,
  siOpensuse,
  siOpenwrt,
  siProxmox,
  siRaspberrypi,
  siRedhat,
  siRockylinux,
  siUbuntu,
  type SimpleIcon,
} from "simple-icons";

const BY_ID: Record<string, SimpleIcon> = {
  almalinux: siAlmalinux,
  alpine: siAlpinelinux,
  arch: siArchlinux,
  centos: siCentos,
  ceph: siCeph,
  darwin: siApple,
  debian: siDebian,
  fedora: siFedora,
  freebsd: siFreebsd,
  gentoo: siGentoo,
  // Not an OS either: a Hetzner Storage Box, told by its host name — see
  // `pick_system` in the backend's ssh.rs.
  hetzner: siHetzner,
  kali: siKalilinux,
  linuxmint: siLinuxmint,
  macos: siApple,
  manjaro: siManjaro,
  minio: siMinio,
  nixos: siNixos,
  opensuse: siOpensuse,
  "opensuse-leap": siOpensuse,
  "opensuse-tumbleweed": siOpensuse,
  openwrt: siOpenwrt,
  pve: siProxmox,
  raspbian: siRaspberrypi,
  rhel: siRedhat,
  rocky: siRockylinux,
  sles: siOpensuse,
  ubuntu: siUbuntu,
};

/** Shown for anything Linux-ish that is not in the table. */
export const GENERIC_ICON = siLinux;

/**
 * Systems that are certainly not Linux and have no mark to draw.
 *
 * simple-icons carries no Windows logo — Microsoft does not license it for
 * reuse — and the penguin is not a near-enough miss to stand in for it. These
 * ids therefore get no icon at all, which says less but says nothing wrong.
 *
 * Reached mainly over FTP, where all the target says about itself is the one
 * word `SYST` answers with: "UNIX" or "Windows_NT" and little else.
 *
 * `objectstore` is the same idea from the other direction: an S3 endpoint that
 * is neither MinIO nor Ceph is named in the tooltip but drawn with nothing,
 * because the alternative would be a Linux penguin for something that is not
 * an operating system. Amazon lands here too — its marks are not licensed for
 * reuse, the same reason there is no Windows logo above.
 */
const UNDRAWABLE = new Set([
  "windows",
  "winnt",
  "os/2",
  "vms",
  "mvs",
  "unknown",
  "objectstore",
  // Only the SSH software is known (`OpenSSH 9.6`), nothing about the system.
  "ssh",
]);

/** `null` where the system is known but has no mark that may be drawn. */
export function osIcon(id: string): SimpleIcon | null {
  const key = id.toLowerCase();
  if (UNDRAWABLE.has(key)) return null;
  return BY_ID[key] ?? GENERIC_ICON;
}

/**
 * Brand colours are chosen for white backgrounds, and a few of them (AlmaLinux
 * and Apple are pure black) disappear on this one. Anything too dark to read
 * gets the normal text colour instead.
 */
export function osIconColor(icon: SimpleIcon): string {
  const value = parseInt(icon.hex, 16);
  const [r, g, b] = [(value >> 16) & 255, (value >> 8) & 255, value & 255];
  // Rec. 601 luma, good enough to tell "readable" from "a hole in the card".
  const luma = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luma < 0.32 ? "currentColor" : `#${icon.hex}`;
}
