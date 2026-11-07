<script setup lang="ts">
import type { SimpleIcon } from "simple-icons";
import { osIconColor } from "../os";

/**
 * The mark of a tool the app works with (1Password, Bitwarden), from
 * simple-icons — the same source and colour rule as the system logos on the
 * cards. Decorative: the tool's name always stands beside it.
 */
defineProps<{ icon: SimpleIcon; size?: number }>();
</script>

<template>
  <svg
    class="brand-icon"
    viewBox="0 0 24 24"
    :width="size ?? 16"
    :height="size ?? 16"
    :fill="osIconColor(icon)"
    aria-hidden="true"
  >
    <path :d="icon.path" />
  </svg>
</template>

<style scoped>
.brand-icon {
  flex: 0 0 auto;
}
</style>
