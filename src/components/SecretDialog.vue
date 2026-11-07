<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Field, Input, PasswordInput } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import type { SecretPrompt } from "../types";

/**
 * "What this connection needs, and what is stored nowhere."
 *
 * Raised for connections whose credential source is "Ask when connecting" —
 * the one option that writes nothing anywhere. What is typed here
 * goes to the backend, which keeps it in memory for as long as the tab lives
 * so parallel transfers do not each ask again, and forgets it when the tab
 * closes.
 *
 * One dialog for both protocols, because the question is the same one twice.
 * Only the words differ: FTP wants a password, S3 a secret access key — and
 * calling the latter a "password" would send people looking for the wrong
 * thing in their provider's console. An encrypted SSH key's passphrase is
 * asked for here as well.
 *
 * The server's own questions during a keyboard-interactive login — a one-time
 * code, say — come here too, as `challenge`, with the server's words as the
 * label. Those are not kept even for the tab: a code is good for one login.
 *
 * Nothing is saved on this side at all: the field is cleared with the dialog,
 * and there is deliberately no "remember" — a connection that should remember
 * its secret has the vault option — 1Password or Bitwarden — which is the
 * better answer to the same wish.
 */
const props = defineProps<{ prompt: SecretPrompt }>();

/** `null` is "Cancel", which fails the connection rather than retrying. */
const emit = defineEmits<{ answer: [secret: string | null] }>();
const { t } = useI18n();

/** Each kind's title, label and question under `SecretDialog.<kind>`. */
const KINDS: readonly SecretPrompt["kind"][] = ["password", "secretKey", "passphrase", "challenge"];

const words = computed(() => {
  const kind = KINDS.includes(props.prompt.kind) ? props.prompt.kind : "password";
  const base = {
    title: t(`SecretDialog.${kind}.title`),
    label: t(`SecretDialog.${kind}.label`),
    asks: t(`SecretDialog.${kind}.asks`),
  };
  const text = props.prompt.challenge?.text.trim().replace(/:$/, "");
  return text ? { ...base, label: text } : base;
});

/** What the server adds to the question, such as where the code was sent. */
const instructions = computed(() => props.prompt.challenge?.instructions.trim() ?? "");

/** A code may be visible while typing, if the server wants it so. */
const visible = computed(() => props.prompt.challenge?.echo ?? false);

/**
 * An S3 access key id is long and is the one thing worth checking before
 * typing a secret next to it, so it is shown as it is. An empty user is an
 * anonymous FTP login.
 */
const who = computed(() => props.prompt.user || "anonymous");

const secret = ref("");
</script>

<template>
  <EditDialog :title="words.title" @save="emit('answer', secret)" @cancel="emit('answer', null)">
    <p class="lead">
      <code>{{ who }}@{{ prompt.host }}:{{ prompt.port }}</code>
      {{ words.asks }}.
      {{
        prompt.kind === "challenge"
          ? t("SecretDialog.oneLogin")
          : t("SecretDialog.thisTab")
      }}
    </p>
    <p v-if="instructions" class="lead">{{ instructions }}</p>

    <Field :label="words.label">
      <!--
        `@keydown.enter` rather than a form: the dialog's own Enter handling
        sits on the wrapper, and a password field is the one place where the
        key is pressed without looking at what is on screen.
      -->
      <Input
        v-if="visible"
        v-model="secret"
        autocomplete="off"
        spellcheck="false"
        data-autofocus
        @keydown.enter.prevent="emit('answer', secret)"
      />
      <PasswordInput
        v-else
        v-model="secret"
        autocomplete="off"
        spellcheck="false"
        data-autofocus
        @keydown.enter.prevent="emit('answer', secret)"
      />
    </Field>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('answer', null)">{{ t("common.cancel") }}</Button>
      <Button @click="emit('answer', secret)">{{ t("SecretDialog.connect") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.lead {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--muted);
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85rem;
  color: var(--fg);
  word-break: break-all;
}

.spacer {
  flex: 1;
}
</style>
