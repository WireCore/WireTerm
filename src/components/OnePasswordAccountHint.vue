<!--
  Where the account name is in the 1Password app: at the top left of the sidebar.

  A schematic, not a replica of the app — without its logo, in the theme's
  colours, so it fits in light and dark. The name is a placeholder.
-->
<script setup lang="ts">
import { useI18n } from "vue-i18n";

const { t } = useI18n();
</script>

<template>
  <svg
    class="hint-image"
    viewBox="0 0 520 230"
    role="img"
    aria-labelledby="op-hint-title op-hint-desc"
  >
    <title id="op-hint-title">{{ t("OnePasswordAccountHint.title") }}</title>
    <desc id="op-hint-desc">
      {{ t("OnePasswordAccountHint.description", { name: t("OnePasswordAccountHint.sampleName") }) }}
    </desc>

    <defs>
      <clipPath id="op-hint-window">
        <rect x="1" y="1" width="360" height="228" rx="12" />
      </clipPath>
    </defs>

    <!-- App window -->
    <g clip-path="url(#op-hint-window)">
      <rect x="1" y="1" width="360" height="228" fill="var(--color-bg-2)" />
      <circle cx="18" cy="16" r="4" fill="var(--color-line-2)" />
      <circle cx="32" cy="16" r="4" fill="var(--color-line-2)" />
      <circle cx="46" cy="16" r="4" fill="var(--color-line-2)" />
      <line x1="1" y1="31" x2="361" y2="31" stroke="var(--color-line)" />

      <!-- Sidebar -->
      <rect x="1" y="32" width="128" height="198" fill="var(--color-card)" />
      <line x1="129" y1="32" x2="129" y2="230" stroke="var(--color-line)" />

      <!-- The account at the top left -->
      <rect x="8" y="40" width="114" height="34" rx="8" fill="var(--color-line)" />
      <circle cx="25" cy="57" r="10" fill="var(--color-info)" fill-opacity="0.25" />
      <text x="25" y="61" text-anchor="middle" font-size="11" font-weight="600" fill="var(--color-info)">
        M
      </text>
      <text x="40" y="61" font-size="11" font-weight="600" fill="var(--color-fg)">
        {{ t("OnePasswordAccountHint.sampleName") }}
      </text>
      <path d="M109 55 l3.5 3.5 l3.5 -3.5" fill="none" stroke="var(--color-muted)" stroke-width="1.5" stroke-linecap="round" />

      <!-- Sidebar entries -->
      <g fill="var(--color-line-2)">
        <rect x="14" y="92" width="70" height="7" rx="3.5" />
        <rect x="14" y="110" width="56" height="7" rx="3.5" />
        <rect x="14" y="128" width="78" height="7" rx="3.5" />
        <rect x="14" y="154" width="40" height="5" rx="2.5" opacity="0.6" />
        <rect x="14" y="170" width="64" height="7" rx="3.5" />
        <rect x="14" y="188" width="52" height="7" rx="3.5" />
      </g>

      <!-- Content -->
      <g fill="var(--color-line)">
        <rect x="144" y="46" width="200" height="22" rx="6" />
        <rect x="144" y="84" width="200" height="30" rx="6" />
        <rect x="144" y="122" width="200" height="30" rx="6" />
        <rect x="144" y="160" width="200" height="30" rx="6" />
      </g>
    </g>
    <rect x="1" y="1" width="360" height="228" rx="12" fill="none" stroke="var(--color-line-2)" />

    <!-- Marker and hint -->
    <rect
      x="4" y="36" width="122" height="42" rx="10"
      fill="none" stroke="var(--color-warn)" stroke-width="2" stroke-dasharray="5 4"
    />
    <path d="M378 57 C 300 57, 220 40, 132 52" fill="none" stroke="var(--color-warn)" stroke-width="2" />
    <path
      d="M140 46 L130 52 L141 58"
      fill="none" stroke="var(--color-warn)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
    />
    <text x="384" y="52" font-size="13" font-weight="600" fill="var(--color-fg)">
      {{ t("OnePasswordAccountHint.line1") }}
    </text>
    <text x="384" y="70" font-size="13" font-weight="600" fill="var(--color-fg)">
      {{ t("OnePasswordAccountHint.line2") }}
    </text>
    <text x="384" y="94" font-size="11" fill="var(--color-muted)">
      {{ t("OnePasswordAccountHint.line3") }}
    </text>
    <text x="384" y="109" font-size="11" fill="var(--color-muted)">
      {{ t("OnePasswordAccountHint.line4") }}
    </text>
  </svg>
</template>

<style scoped>
.hint-image {
  display: block;
  width: 100%;
  height: auto;
  font-family: var(--font-sans);
}
</style>
