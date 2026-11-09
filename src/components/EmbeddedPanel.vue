<script setup lang="ts">
/**
 * A settings tab that holds an edit dialog: that one then shows as the tab's
 * content instead of as a window of its own (see `EMBEDDED` in EditDialog).
 */
import { provide } from "vue";
import { EMBEDDED } from "./EditDialog.vue";

provide(EMBEDDED, true);
</script>

<template>
  <slot />
</template>
