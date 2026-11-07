<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { useI18n } from "vue-i18n";
import { SegmentedControl, SegmentedControlItem } from "@wirecore/wirelayer-vue";
import FileBrowser from "./FileBrowser.vue";
import SshTerminal from "./SshTerminal.vue";
import {
  hasTerminal,
  type ConnectionSettings,
  type ConnectionView,
  type ForwardStatus,
  type RemoteSystem,
  type TabStatus,
} from "../types";

/**
 * What one tab shows.
 *
 * Over SSH that is two things: a shell and a file browser, and they are not
 * two connections but two channels on one — SFTP is a subsystem of SSH, so the
 * login and the host-key question happen once, for whichever of the two is
 * opened first. This component owns that connection on behalf of both and is
 * the only place that hangs it up.
 *
 * Over FTP and over S3 there is only the file browser. Neither has anything
 * resembling a shell at the other end, so the switch is not drawn at all
 * rather than offering a half that does not exist.
 */
const props = defineProps<{
  /** Identifies the session in the backend; stable for this tab's lifetime. */
  sessionId: string;
  connectionId: string;
  settings: ConnectionSettings;
  /** Hidden tabs stay mounted, so the session survives a tab switch. */
  active: boolean;
}>();

// Both travel up from whichever half is in a position to know: the tab shows
// the state, and the overview stores what the target turned out to be.
const emit = defineEmits<{
  status: [status: TabStatus];
  system: [system: RemoteSystem];
}>();
const { t } = useI18n();

const terminal = computed(() => hasTerminal(props.settings));

const view = ref<ConnectionView>(terminal.value ? "terminal" : "files");

/**
 * The file browser is built the first time it is asked for, and kept after
 * that.
 *
 * Building it eagerly on an SSH tab would open an SFTP channel whether or not
 * anyone wanted one; unmounting it on the way back to the terminal would lose
 * both panes' directories and any queue still running. Where it is the only
 * view there is, it starts out built.
 */
const filesOpened = ref(!terminal.value);
watch(view, (current) => {
  if (current === "files") filesOpened.value = true;
});

// ---- Port forwards --------------------------------------------------------------
//
// They start as soon as the terminal is connected — over the same login — and
// end with the tab. Their state is polled as long as there are any: how many
// connections are passing through changes on its own.

const forwards = ref<ForwardStatus[]>([]);
let polling: ReturnType<typeof setInterval> | undefined;

async function startForwards() {
  if (props.settings.type !== "ssh" || !props.settings.forwards?.length) return;
  try {
    forwards.value = await invoke<ForwardStatus[]>("ssh_forwards_start", {
      sessionId: props.sessionId,
      settings: JSON.parse(JSON.stringify(props.settings)),
    });
  } catch (e) {
    forwards.value = [
      { kind: "local", label: t("ConnectionPane.forwards"), active: false, error: String(e), connections: 0 },
    ];
    return;
  }
  clearInterval(polling);
  polling = setInterval(async () => {
    forwards.value = await invoke<ForwardStatus[]>("ssh_forwards_status", {
      sessionId: props.sessionId,
    }).catch(() => forwards.value);
  }, 3000);
}

function terminalStatus(status: TabStatus) {
  emit("status", status);
  if (status === "connected") startForwards();
}

function forwardText(forward: ForwardStatus): string {
  // With port 0 there is usually nothing useful in the label — then the chosen one.
  const label = forward.port ? forward.label.replace(/:0\b/, `:${forward.port}`) : forward.label;
  return forward.connections ? `${label} · ${forward.connections}` : label;
}

onBeforeUnmount(() => {
  clearInterval(polling);
  // The views close their own channels as they unmount. This is what actually
  // hangs up, and it is the only place that does.
  invoke("session_close", { sessionId: props.sessionId }).catch(() => {});
});
</script>

<template>
  <section class="connection">
    <!--
      Two channels on one connection, so this switches what is on screen and
      nothing else: neither side is disconnected by looking at the other. Drawn
      only where there are two of them.
    -->
    <div v-if="terminal" class="switch">
      <SegmentedControl v-model="view" required :label="t('ConnectionPane.view')" size="sm">
        <SegmentedControlItem value="terminal">SSH</SegmentedControlItem>
        <SegmentedControlItem value="files">SFTP</SegmentedControlItem>
      </SegmentedControl>
      <ul v-if="forwards.length" class="forwards" :aria-label="t('ConnectionPane.portForwards')">
        <li
          v-for="(forward, index) in forwards"
          :key="index"
          :class="{ failed: !forward.active }"
          :title="forward.error ?? (forward.connections ? t('ConnectionPane.openConnections', forward.connections) : t('ConnectionPane.ready'))"
        >
          {{ forwardText(forward) }}
        </li>
      </ul>
    </div>

    <div class="body">
      <div v-if="terminal" v-show="view === 'terminal'" class="layer">
        <SshTerminal
          v-if="settings.type === 'ssh'"
          :session-id="sessionId"
          :connection-id="connectionId"
          :settings="settings"
          :active="active && view === 'terminal'"
          @status="terminalStatus"
          @system="emit('system', $event)"
        />
      </div>

      <div v-if="filesOpened" v-show="view === 'files'" class="layer">
        <!--
          The terminal reports the tab's state where there is one; where there
          is not, the browser is the connection and says so itself.
        -->
        <FileBrowser
          :session-id="sessionId"
          :settings="settings"
          :active="active && view === 'files'"
          @status="terminal || emit('status', $event)"
          @system="emit('system', $event)"
        />
      </div>
    </div>
  </section>
</template>

<style scoped>
.connection {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
}

.switch {
  flex: 0 0 auto;
  display: flex;
  align-items: center;
  gap: 0.15rem;
  padding: 0.4rem 1rem 0;
}

.forwards {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin: 0 0 0 1rem;
  padding: 0;
  list-style: none;
  font-family: Consolas, Menlo, monospace;
  font-size: 0.78rem;
  color: var(--muted);
}

.forwards li::before {
  content: "⇄ ";
}

.forwards li.failed {
  color: var(--color-danger, #c33);
  text-decoration: line-through;
}

.body {
  position: relative;
  flex: 1;
  min-height: 0;
}

/* Both stacked rather than swapped: the terminal must keep its size while the
   file browser is in front, or xterm re-lays-out on every switch. */
.layer {
  position: absolute;
  inset: 0;
}
</style>
