<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Spinner } from "@wirecore/wirelayer-vue";
import OsIcon from "./OsIcon.vue";
import { reportVaultProblem } from "../vault";
import { probe } from "../remote";
import { withJumps } from "../store";
import type { Connection, ConnectionProbe } from "../types";

/** "Test connection" against a draft that has not been saved yet. */
const props = defineProps<{ connection: Connection }>();
const { t } = useI18n();

const testing = ref(false);
/** null while nothing has been tried since the last edit. */
const result = ref<
  { ok: true; probe: ConnectionProbe } | { ok: false; message: string } | null
>(null);

/**
 * A test without these cannot get as far as a login. An anonymous FTP login
 * needs no user name — it does not use the field at all.
 */
const testable = computed(
  () =>
    props.connection.settings.host.trim() !== "" &&
    (props.connection.settings.user.trim() !== "" ||
      props.connection.settings.auth.source === "anonymous"),
);

/**
 * Runs against the draft, not the stored connection: the point is to find out
 * whether what is on screen works, before it is saved.
 */
async function test() {
  testing.value = true;
  result.value = null;
  try {
    const outcome = await probe(withJumps(props.connection.settings));
    result.value = { ok: true, probe: outcome };
    // A successful test has just learned what the target is, so the card does
    // not have to wait for the first real login to show it.
    if (outcome.system) props.connection.system = outcome.system;
  } catch (e) {
    // A vault that needs sorting out raises its own dialog; the test is simply
    // left without a result, to be run again afterwards.
    if (!reportVaultProblem(String(e))) result.value = { ok: false, message: String(e) };
  } finally {
    testing.value = false;
  }
}
</script>

<template>
  <div class="test">
    <Button variant="outline" :disabled="testing || !testable" @click="test">
      {{ testing ? t("ConnectionTest.testing") : t("ConnectionTest.test") }}
    </Button>

    <p v-if="testing" class="outcome"><Spinner size="sm" />{{ t("ConnectionTest.connecting") }}</p>

    <p v-else-if="result?.ok" class="outcome ok">
      <span class="mark">✓</span>
      <span>{{ t("ConnectionTest.connected", { millis: result.probe.millis }) }}</span>
      <template v-if="result.probe.system">
        <span class="sep">·</span>
        <OsIcon :id="result.probe.system.id" />
        <span :title="result.probe.system.pretty">
          {{ result.probe.system.name }} {{ result.probe.system.version }}
        </span>
      </template>
    </p>

    <p v-else-if="result" class="outcome failed">
      <span class="mark">✗</span>
      <span>{{ result.message }}</span>
    </p>
  </div>
</template>

<style scoped>
.test {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
}

.test > button {
  flex: 0 0 auto;
}

.outcome {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin: 0;
  padding-top: 0.45em;
  min-width: 0;
  font-size: 0.85rem;
  color: var(--muted);
  line-height: 1.4;
}

.outcome.ok {
  color: var(--ok);
}

/* The message is whatever the server or the key source said, so it can be
   long and is not worth truncating. */
.outcome.failed {
  color: var(--danger);
  word-break: break-word;
}

.mark {
  font-weight: 700;
}

.sep {
  opacity: 0.5;
}
</style>
