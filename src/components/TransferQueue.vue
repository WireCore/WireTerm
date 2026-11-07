<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Badge, Button, IconButton, Progress } from "@wirecore/wirelayer-vue";
import { ChevronDown, ChevronRight, RotateCw, X } from "@lucide/vue";
import { formatBytes, formatDuration, formatSpeed } from "../sftp";
import type { Transfer } from "../types";

/**
 * The queue at the foot of the file browser.
 *
 * What makes a transfer legible is not the percentage but the two times: how
 * long it has been running and how much longer it has to go. Both are worked
 * out here from the bytes that have arrived, because the backend reports
 * nothing but a running total — it has no idea how fast the line is either.
 *
 * A transfer that succeeds leaves the list at once, so what is on screen is
 * always what is still outstanding or still wrong. What went well is left as
 * the count in the header; a row saying "done" is not information anyone
 * comes back to.
 */
const props = defineProps<{
  transfers: Transfer[];
  /** Finished and gone from the list — all that is left of them. */
  completed: number;
  /** Their bytes, added up, for the same reason. */
  completedBytes: number;
  /**
   * Owned above, because the pane's height depends on it: collapsed, the queue
   * is only its header and must not hold on to the height it was dragged to.
   */
  collapsed: boolean;
}>();

const emit = defineEmits<{
  cancel: [id: string];
  retry: [id: string];
  dismiss: [id: string];
  cancelAll: [];
  "update:collapsed": [collapsed: boolean];
}>();
const { t } = useI18n();

/**
 * Ticks only while something is running: the elapsed time has to move on its
 * own between progress events, and there is nothing to move once it stops.
 */
const now = ref(performance.now());
let timer: ReturnType<typeof setInterval> | undefined;

const running = computed(() => props.transfers.some((transfer) => transfer.status === "running"));

watch(
  running,
  (active) => {
    clearInterval(timer);
    timer = active ? setInterval(() => (now.value = performance.now()), 250) : undefined;
  },
  { immediate: true },
);

onBeforeUnmount(() => clearInterval(timer));

const counts = computed(() => {
  const tally = { queued: 0, running: 0, done: 0, error: 0, cancelled: 0 };
  for (const transfer of props.transfers) tally[transfer.status] += 1;
  return tally;
});

const idle = computed(() => !props.transfers.length && props.completed === 0);

/** How long a transfer has been going: frozen once it has ended. */
function elapsed(transfer: Transfer): number {
  if (transfer.elapsed !== undefined) return transfer.elapsed;
  if (transfer.startedAt === undefined) return 0;
  return now.value - transfer.startedAt;
}

/**
 * Averaged over the whole transfer rather than the last moment. A rate taken
 * between two progress events jumps around far too much to read, and the
 * average is also what the estimate below wants.
 *
 * Suppressed for the first quarter second, where the divisor is small enough
 * to produce a nonsense figure.
 */
function speed(transfer: Transfer): number {
  const millis = elapsed(transfer);
  return millis > 250 ? (transfer.transferred / millis) * 1000 : 0;
}

/** null where there is nothing to go on — no size, or not moving yet. */
function remaining(transfer: Transfer): number | null {
  if (transfer.status !== "running" || !transfer.size) return null;
  const rate = speed(transfer);
  if (rate <= 0) return null;
  return ((transfer.size - transfer.transferred) / rate) * 1000;
}

function percent(transfer: Transfer): number {
  if (transfer.status === "done") return 100;
  if (!transfer.size) return 0;
  return Math.min(100, (transfer.transferred / transfer.size) * 100);
}

/** The bar's text: a word for a transfer that is not moving, the percentage for one that is. */
function barText(transfer: Transfer): string {
  if (transfer.status === "running") {
    return t("TransferQueue.percent", { value: Math.round(percent(transfer)) });
  }
  return t(`TransferQueue.status.${transfer.status}`);
}
</script>

<template>
  <section class="queue" :class="{ collapsed }">
    <header class="head">
      <Button
        class="toggle"
        variant="text"
        size="xs"
        :leading-icon="collapsed ? ChevronRight : ChevronDown"
        :title="collapsed ? t('TransferQueue.expand') : t('TransferQueue.collapse')"
        @click="emit('update:collapsed', !collapsed)"
      >
        {{ t("TransferQueue.title") }}
      </Button>

      <span class="tally">
        <Badge v-if="counts.running" variant="info">{{
          t("TransferQueue.running", { n: counts.running })
        }}</Badge>
        <Badge v-if="counts.queued">{{ t("TransferQueue.queued", { n: counts.queued }) }}</Badge>
        <!-- The only trace successful transfers leave, since their rows go. -->
        <Badge v-if="completed" variant="success">
          {{ t("TransferQueue.completed", { n: completed, size: formatBytes(completedBytes) }) }}
        </Badge>
        <Badge v-if="counts.error" variant="danger">{{
          t("TransferQueue.failed", { n: counts.error })
        }}</Badge>
        <Badge v-if="counts.cancelled" variant="outline">{{
          t("TransferQueue.cancelled", { n: counts.cancelled })
        }}</Badge>
        <span v-if="idle" class="muted">{{ t("TransferQueue.none") }}</span>
      </span>

      <span class="spacer"></span>
      <Button
        variant="text"
        size="xs"
        :disabled="!counts.running && !counts.queued"
        @click="emit('cancelAll')"
      >
        {{ t("TransferQueue.cancelAll") }}
      </Button>
    </header>

    <div v-if="!collapsed" class="rows">
      <div v-for="transfer in transfers" :key="transfer.id" class="row">
        <span
          class="dir"
          :title="transfer.direction === 'download' ? t('TransferQueue.download') : t('TransferQueue.upload')"
        >
          {{ transfer.direction === "download" ? "↓" : "↑" }}
        </span>

        <span class="name" :title="`${transfer.local}\n${transfer.remote}`">
          {{ transfer.name }}
        </span>

        <!--
          The bar is the state for a running transfer and the outcome for one
          that stopped, so it stays on screen either way rather than being
          swapped for a word.
        -->
        <Progress
          :value="percent(transfer)"
          :label="transfer.name"
          size="xs"
          hide-label
          :show-value="false"
          :status="transfer.status === 'error' ? 'danger' : transfer.status === 'cancelled' ? 'neutral' : undefined"
          :bar-text="barText(transfer)"
        />

        <span class="figure">
          {{ formatBytes(transfer.transferred) }}
          <span v-if="transfer.size" class="muted">/ {{ formatBytes(transfer.size) }}</span>
        </span>

        <span class="figure muted">{{
          transfer.status === "running" ? formatSpeed(speed(transfer)) : ""
        }}</span>

        <!-- Elapsed and estimated side by side: the second only means
             something next to the first. -->
        <span class="figure muted">
          {{ transfer.startedAt === undefined ? "–" : formatDuration(elapsed(transfer)) }}
          <template v-if="remaining(transfer) !== null">
            / ~{{ formatDuration(remaining(transfer) ?? 0) }}
          </template>
        </span>

        <span class="actions">
          <template v-if="transfer.status === 'running' || transfer.status === 'queued'">
            <IconButton
              :icon="X"
              :label="t('common.cancel')"
              :title="t('common.cancel')"
              variant="text"
              size="xs"
              @click="emit('cancel', transfer.id)"
            />
          </template>
          <!--
            Two verbs, because these are the rows that stay: one carries on
            from where the transfer stopped, the other gives it up — and says
            so, since what it throws away is what "try again" would
            have continued from.
          -->
          <template v-else>
            <IconButton
              :icon="RotateCw"
              :label="t('TransferQueue.retry')"
              :title="t('TransferQueue.retryTitle')"
              variant="text"
              size="xs"
              @click="emit('retry', transfer.id)"
            />
            <IconButton
              :icon="X"
              :label="t('TransferQueue.dismiss')"
              :title="t('TransferQueue.dismissTitle')"
              variant="text"
              size="xs"
              @click="emit('dismiss', transfer.id)"
            />
          </template>
        </span>
      </div>

      <p v-if="!transfers.length" class="empty">
        {{ t("TransferQueue.empty") }}
      </p>
    </div>

    <!-- Out of the rows and onto its own line: an error message is a sentence,
         and a sentence does not fit in a table cell. -->
    <Alert
      v-for="failed in transfers.filter((entry) => entry.error)"
      :key="`e-${failed.id}`"
      class="failure"
      status="danger"
      variant="simple"
      size="sm"
    >
      <strong>{{ failed.name }}:</strong> {{ failed.error }}
    </Alert>
  </section>
</template>

<style scoped>
.queue {
  display: flex;
  flex-direction: column;
  min-height: 0;
  background: var(--color-bg-2);
  border: 1px solid var(--color-line);
  border-radius: 8px;
  overflow: hidden;
}

.head {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.3rem 0.5rem;
  border-bottom: 1px solid var(--color-line);
}

.queue.collapsed .head {
  border-bottom: none;
}

.toggle {
  flex: 0 0 auto;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.tally {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.8rem;
  color: var(--color-muted);
  white-space: nowrap;
  overflow: hidden;
}

.spacer {
  flex: 1;
}

.rows {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
}

.row {
  display: grid;
  grid-template-columns: 1.1rem minmax(6rem, 1fr) minmax(7rem, 1.4fr) 10rem 6.5rem 9rem 4rem;
  align-items: center;
  gap: 0.55rem;
  padding: 0.2rem 0.6rem;
  font-size: 0.85rem;
  white-space: nowrap;
}

.row:hover {
  background: var(--color-line);
}

.dir {
  text-align: center;
  color: var(--color-primary);
}

.name {
  overflow: hidden;
  text-overflow: ellipsis;
}

.figure {
  font-variant-numeric: tabular-nums;
  overflow: hidden;
  text-overflow: ellipsis;
}

.muted {
  color: var(--color-muted);
}

/* Right-aligned so the one button of a running row sits where the second of a
   stopped row does, and the column does not shuffle as rows change state. */
.actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.1rem;
}

.empty {
  margin: 1.1rem 0;
  text-align: center;
  color: var(--color-muted);
  font-size: 0.85rem;
}

.failure {
  padding: 0.25rem 0.6rem;
  word-break: break-word;
}
</style>
