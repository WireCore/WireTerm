<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Code, Descriptions } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import type { HostKeyPrompt } from "../types";

/**
 * "Unknown host — trust it?"
 *
 * Nothing is saved here: the answer goes back to the backend, which is where
 * the trusted keys are kept. Cancelling is a full answer too, and the only one
 * that lets the connection fail closed, so there is no way out of this dialog
 * that leaves the question hanging.
 */
const props = defineProps<{ prompt: HostKeyPrompt }>();

const emit = defineEmits<{ answer: [trust: boolean] }>();
const { t } = useI18n();

/**
 * A key that *changed* is asked twice. Either the server was rebuilt, which
 * the user knows about, or someone is sitting in between, which they very much
 * do not — and one misplaced click should not be enough to wave that through.
 */
const confirming = ref(false);

function accept() {
  if (props.prompt.changed && !confirming.value) {
    confirming.value = true;
    return;
  }
  emit("answer", true);
}

/**
 * A server certificate rather than a host key. Same question, same answer —
 * trust exactly this one, or do not connect — but other words for it.
 */
const tls = computed(() => props.prompt.kind === "tls");

const title = computed(() => {
  if (tls.value) {
    return props.prompt.changed ? t("HostKeyDialog.titleCertChanged") : t("HostKeyDialog.titleCertUnknown");
  }
  return props.prompt.changed ? t("HostKeyDialog.titleKeyChanged") : t("HostKeyDialog.titleHostUnknown");
});

const rows = computed(() => [
  {
    label: "Host",
    value:
      tls.value || props.prompt.port !== 22
        ? `${props.prompt.host}:${props.prompt.port}`
        : props.prompt.host,
  },
  {
    label: t("HostKeyDialog.type"),
    value: tls.value ? t("HostKeyDialog.tlsCertificate") : props.prompt.algorithm,
  },
  ...(tls.value && props.prompt.reason
    ? [{ label: t("HostKeyDialog.reason"), value: props.prompt.reason }]
    : []),
  { id: "fingerprint", label: "Fingerprint" },
]);

/**
 * What the key is called in `/etc/ssh`, so the check below is a command that
 * can be pasted rather than one that has to be worked out. Unknown algorithms
 * fall back to a glob, which still finds the right file.
 */
const keyFileType = computed(() => {
  const algorithm = props.prompt.algorithm;
  if (algorithm.includes("ed25519")) return "ed25519";
  if (algorithm.includes("ecdsa")) return "ecdsa";
  if (algorithm.includes("rsa")) return "rsa";
  return "*";
});
</script>

<template>
  <!--
    No `@save`, so Enter does nothing here — the one dialog in the app where it
    does not confirm. Trusting a key the machine has never seen is the decision
    this whole dialog exists to slow down, and it must not be answered by a
    keystroke aimed at whatever was on screen a moment earlier. Escape still
    declines, which is the safe half.
  -->
  <EditDialog :title="title" @cancel="emit('answer', false)">
    <Alert v-if="prompt.changed && tls" status="danger" class="alarm">
      {{ t("HostKeyDialog.certChanged") }}
    </Alert>
    <Alert v-else-if="prompt.changed" status="danger" class="alarm">
      {{ t("HostKeyDialog.keyChanged") }}
    </Alert>
    <p v-else-if="tls" class="lead">{{ t("HostKeyDialog.certUnknown") }}</p>
    <p v-else class="lead">{{ t("HostKeyDialog.hostUnknown") }}</p>

    <Descriptions
      orientation="horizontal"
      :columns="1"
      :classes="{ list: 'gap-y-2', item: 'grid-cols-[6rem_minmax(0,1fr)]' }"
      :items="rows"
    >
      <template #value-fingerprint>
        <Code class="box">{{ prompt.fingerprint }}</Code>
      </template>
    </Descriptions>

    <!--
      The same string `ssh-keyscan` prints, so the two can be held side by side
      without anyone having to convert a format in their head.
    -->
    <i18n-t v-if="tls" keypath="HostKeyDialog.verify" tag="p" class="hint">
      <template #command>
        <Code>openssl x509 -noout -fingerprint -sha256 -in {{ t("HostKeyDialog.certFile") }}</Code>
      </template>
    </i18n-t>
    <i18n-t v-else keypath="HostKeyDialog.verify" tag="p" class="hint">
      <template #command>
        <Code>ssh-keygen -lf /etc/ssh/ssh_host_{{ keyFileType }}_key.pub</Code>
      </template>
    </i18n-t>

    <template #actions>
      <p v-if="confirming" class="confirm">{{ t("HostKeyDialog.confirm") }}</p>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('answer', false)">{{ t("common.cancel") }}</Button>
      <Button :variant="prompt.changed ? 'danger' : 'primary'" @click="accept">
        {{
          confirming
            ? t("HostKeyDialog.trustConfirmed")
            : prompt.changed
              ? t("HostKeyDialog.trustAnyway")
              : t("HostKeyDialog.trust")
        }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.lead,
.alarm {
  margin: 0 0 1rem;
}

.lead {
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--muted);
}

/* The fingerprint as a block of its own: it is compared character by character. */
.box {
  display: block;
  padding: 0.35em 0.5em;
  word-break: break-all;
}

.hint {
  margin: 1rem 0 0;
  font-size: 0.8rem;
  line-height: 1.6;
  color: var(--muted);
}

.confirm {
  margin: 0;
  min-width: 0;
  font-size: 0.9rem;
  color: var(--warn);
}

.spacer {
  flex: 1;
}
</style>
