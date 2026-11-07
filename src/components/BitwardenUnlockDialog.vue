<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  Alert,
  Button,
  Field,
  Input,
  PasswordInput,
  type TextFieldHandle,
} from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { reportVaultProblem, unlockBitwarden } from "../vault";
import type { BitwardenAccount } from "../types";

/**
 * "The vault is locked."
 *
 * Bitwarden has no desktop integration WireTerm could ask the way 1Password's
 * is asked: the master password is what opens the vault, and there is no way
 * around typing it. It goes straight to the backend, which derives the keys
 * from it and keeps neither the password nor anything on disk — see
 * src-tauri/src/bitwarden/mod.rs.
 *
 * The code field only appears once the server has actually asked for a second
 * factor, and says which kind: an empty box labelled "Code" in front of
 * someone whose account has no second factor is a question with no answer.
 *
 * Unlike the other dialogs here, this one calls the backend itself rather than
 * handing an answer up: a wrong password has to be reported *in* the dialog
 * and tried again, and passing it out and back would mean carrying it through
 * another component on the way.
 */
const props = defineProps<{
  account: BitwardenAccount;
  reason: string;
  /** The second factor the server asked for, or "" when it asked for none. */
  twoFactor: string;
}>();

const emit = defineEmits<{ done: []; cancel: [] }>();
const { t } = useI18n();

const password = ref("");
const code = ref("");
const busy = ref(false);
const error = ref("");
const codeField = ref<TextFieldHandle>();

const where = computed(() => props.account.server.trim() || "bitwarden.com");

const valid = computed(() => password.value.length > 0 && !busy.value);

/**
 * The code field appears mid-dialog when the server turns out to want one, so
 * the cursor has to follow it there. The dialog is deliberately not remounted
 * for that: the password is already typed and retyping it would be the one
 * thing worse than the extra field.
 */
watch(
  () => props.twoFactor,
  async (wanted) => {
    if (!wanted) return;
    await nextTick();
    codeField.value?.focus();
  },
);

async function unlock() {
  if (!valid.value) return;
  busy.value = true;
  error.value = "";
  try {
    await unlockBitwarden(password.value, code.value);
    password.value = "";
    code.value = "";
    emit("done");
  } catch (e) {
    // A marker is not an error to show: it means the server has just said what
    // it still wants, and raising it reopens this dialog with that field —
    // usually the code. Everything else is a real refusal and belongs on
    // screen, with the password left in place to correct.
    error.value = reportVaultProblem(String(e)) ? "" : String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('BitwardenUnlockDialog.title')" @save="unlock" @cancel="emit('cancel')">
    <Alert status="warn" size="sm" class="reason">{{ reason }}</Alert>

    <i18n-t keypath="BitwardenUnlockDialog.accountOn" tag="p" class="lead">
      <template #email><code>{{ account.email }}</code></template>
      <template #server><code>{{ where }}</code></template>
    </i18n-t>

    <!-- `data-autofocus`: the field the dialog's focus trap starts in — the code, once one is asked for. -->
    <Field :label="t('BitwardenUnlockDialog.masterPassword')">
      <PasswordInput
        v-model="password"
        autocomplete="off"
        spellcheck="false"
        :data-autofocus="twoFactor ? undefined : ''"
        :disabled="busy"
        @keydown.enter.prevent="unlock"
      />
    </Field>

    <Field v-if="twoFactor" :label="t('BitwardenUnlockDialog.code', { method: twoFactor })" class="spaced">
      <Input
        ref="codeField"
        v-model="code"
        autocomplete="off"
        spellcheck="false"
        data-autofocus
        inputmode="numeric"
        :disabled="busy"
        @keydown.enter.prevent="unlock"
      />
    </Field>

    <Alert v-if="error" status="danger" size="sm" class="error">{{ error }}</Alert>

    <p class="hint">{{ t("BitwardenUnlockDialog.hint") }}</p>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" :disabled="busy" @click="emit('cancel')">{{ t("common.cancel") }}</Button>
      <Button :disabled="!valid" @click="unlock">
        {{ busy ? t("BitwardenUnlockDialog.unlocking") : t("BitwardenUnlockDialog.unlock") }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.reason {
  margin-bottom: 0.5rem;
}

.lead {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  color: var(--muted);
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85rem;
  color: var(--fg);
  word-break: break-all;
}

.spaced {
  margin-top: 0.75rem;
}

.error {
  margin-top: 0.75rem;
  word-break: break-word;
}

.hint {
  margin: 0.75rem 0 0;
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--muted);
}

.spacer {
  flex: 1;
}
</style>
