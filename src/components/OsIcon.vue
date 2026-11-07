<script setup lang="ts">
import { computed } from "vue";
import { osIcon, osIconColor } from "../os";

const props = defineProps<{
  /** The os-release `ID` of the target system. */
  id: string;
  size?: number;
}>();

/**
 * `null` for a system that has no mark anyone may draw — see [`osIcon`]. The
 * name beside this stays either way, so nothing is lost but the picture.
 */
const icon = computed(() => osIcon(props.id));
</script>

<template>
  <svg
    v-if="icon"
    class="os-icon"
    viewBox="0 0 24 24"
    :width="size ?? 13"
    :height="size ?? 13"
    :fill="osIconColor(icon)"
    role="img"
    :aria-label="icon.title"
  >
    <title>{{ icon.title }}</title>
    <path :d="icon.path" />
  </svg>
</template>

<style scoped>
.os-icon {
  flex: 0 0 auto;
  vertical-align: -0.12em;
}
</style>
