<script setup lang="ts">
/**
 * The master password: set up, enter, change, forget.
 *
 * It is not the sign-in password. The difference is the whole point:
 *
 * |               | Sign-in password          | Master password                   |
 * | ------------- | ------------------------- | --------------------------------- |
 * | what for      | signing in to the server  | unlocking the secrets             |
 * | where it is   | as a hash on the server   | **nowhere**, not even as a hash   |
 * | resettable    | yes, by mail              | no — use the recovery codes       |
 *
 * That is why there is a "forgot" here that does not lead to the server but to
 * a piece of paper. And that is why the codes are shown **once**: the server
 * does not know them and cannot send them again.
 */
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import {
  Alert,
  Button,
  Checkbox,
  Field,
  IconButton,
  Input,
  PasswordInput,
  Spinner,
} from "@wirecore/wirelayer-vue";
import { Check, Copy } from "@lucide/vue";
import EditDialog from "./EditDialog.vue";
import {
  accountOf,
  changeMaster,
  keyStatus,
  recoverMaster,
  setupMaster,
  unlock,
  type KeyStatus,
} from "../cloud";

const props = defineProps<{
  accountId: string;
  /** What the dialog opens with. "auto" decides by the key status. */
  start?: "auto" | "change";
}>();

const emit = defineEmits<{ done: []; cancel: [] }>();
const { t } = useI18n();

type Step = "loading" | "setup" | "unlock" | "recover" | "change" | "codes";

const step = ref<Step>("loading");
const status = ref<KeyStatus | null>(null);

const password = ref("");
const repeat = ref("");
const oldPassword = ref("");
const code = ref("");

const codes = ref<string[]>([]);
const written = ref(false);
const copied = ref(false);

const busy = ref(false);
const error = ref("");
const dialog = ref<InstanceType<typeof EditDialog>>();

const account = computed(() => accountOf(props.accountId));

const title = computed(() => {
  switch (step.value) {
    case "setup":
      return t("MasterPasswordDialog.title.setup");
    case "recover":
      return t("MasterPasswordDialog.title.recover");
    case "change":
      return t("MasterPasswordDialog.title.change");
    case "codes":
      return t("MasterPasswordDialog.title.codes");
    default:
      return t("MasterPasswordDialog.title.default");
  }
});

/** Two equal, non-empty entries — wherever a new one is set. */
const newPasswordOk = computed(
  () => password.value.length > 0 && password.value === repeat.value,
);

/**
 * Whether this step creates a new set of recovery codes.
 *
 * That decides whether it takes a while: every code is another wrapping of the
 * same private key, and each costs an Argon2id run over 64 MiB. Eight codes
 * plus the master password are nine of them — noticeable, and therefore
 * announced instead of leaving the button silently stuck.
 */
const makesCodes = computed(() =>
  ["setup", "recover", "change"].includes(step.value),
);

/** What the button says — also while it works. */
const confirmLabel = computed(() => {
  if (!busy.value) {
    switch (step.value) {
      case "codes":
        return t("common.done");
      case "unlock":
        return t("MasterPasswordDialog.unlock");
      default:
        return t("common.save");
    }
  }
  switch (step.value) {
    case "setup":
      return t("MasterPasswordDialog.busy.setup");
    case "recover":
      return t("MasterPasswordDialog.busy.recover");
    case "change":
      return t("MasterPasswordDialog.busy.change");
    default:
      return t("MasterPasswordDialog.busy.unlock");
  }
});

const valid = computed(() => {
  switch (step.value) {
    case "setup":
      return newPasswordOk.value;
    case "unlock":
      return password.value.length > 0;
    case "recover":
      return code.value.trim().length > 0 && newPasswordOk.value;
    case "change":
      return oldPassword.value.length > 0 && newPasswordOk.value;
    case "codes":
      return written.value;
    default:
      return false;
  }
});

onMounted(load);

watch(step, () => {
  error.value = "";
  // Focus should land where typing happens next — after a step change that is
  // a different field.
  void nextTick(() => dialog.value?.focusFirst());
});

async function load() {
  try {
    const current = await keyStatus(props.accountId);
    status.value = current;
    if (props.start === "change") step.value = "change";
    else step.value = current.hasKeys ? "unlock" : "setup";
  } catch (e) {
    error.value = String(e);
    step.value = "unlock";
  }
}

function clearFields() {
  password.value = "";
  repeat.value = "";
  oldPassword.value = "";
  code.value = "";
}

async function submit() {
  if (!valid.value || busy.value) return;

  if (step.value === "codes") {
    emit("done");
    return;
  }

  busy.value = true;
  error.value = "";
  try {
    if (step.value === "setup") {
      codes.value = await setupMaster(props.accountId, password.value);
      clearFields();
      step.value = "codes";
    } else if (step.value === "unlock") {
      await unlock(props.accountId, password.value);
      clearFields();
      emit("done");
    } else if (step.value === "recover") {
      codes.value = await recoverMaster(props.accountId, code.value, password.value);
      clearFields();
      step.value = "codes";
    } else if (step.value === "change") {
      codes.value = await changeMaster(props.accountId, oldPassword.value, password.value);
      clearFields();
      step.value = "codes";
    }
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

let copiedTimer: ReturnType<typeof setTimeout> | undefined;

async function copyCodes() {
  try {
    await navigator.clipboard.writeText(codes.value.join("\n"));
    copied.value = true;
    // The check mark goes away again: it is the answer to a click, not a
    // state. Whoever wants to copy a second time should see the button again.
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => (copied.value = false), 2000);
  } catch {
    // No access to the clipboard: the codes are right next to it and can be
    // selected. An error banner for it would be noise.
    copied.value = false;
  }
}
</script>

<template>
  <EditDialog ref="dialog" :title="title" :can-save="valid" @save="submit" @cancel="emit('cancel')">
    <p v-if="account" class="who">
      {{ account.email }}
      <span class="muted">{{ t("MasterPasswordDialog.onServer", { server: account.server }) }}</span>
    </p>

    <template v-if="step === 'loading'">
      <p class="hint">{{ t("MasterPasswordDialog.checking") }}</p>
    </template>

    <!-- Set up: once per account, and it really only works once. -->
    <template v-else-if="step === 'setup'">
      <p class="hint">{{ t("MasterPasswordDialog.setupHint") }}</p>

      <Field :label="t('MasterPasswordDialog.masterPassword')" class="spaced">
        <PasswordInput v-model="password" autocomplete="new-password" />
      </Field>
      <Field
        :label="t('MasterPasswordDialog.repeat')"
        class="spaced"
        :error="repeat && !newPasswordOk ? t('MasterPasswordDialog.mismatch') : undefined"
      >
        <PasswordInput v-model="repeat" autocomplete="new-password" />
      </Field>
    </template>

    <!-- Enter: the normal case, once per start and after a quarter of an hour. -->
    <template v-else-if="step === 'unlock'">
      <p class="hint">{{ t("MasterPasswordDialog.unlockHint") }}</p>

      <Field :label="t('MasterPasswordDialog.masterPassword')" class="spaced">
        <PasswordInput v-model="password" />
      </Field>
    </template>

    <!-- Forgot: the path that does not go through the server. -->
    <template v-else-if="step === 'recover'">
      <p class="hint">{{ t("MasterPasswordDialog.recoverHint") }}</p>

      <Field :label="t('MasterPasswordDialog.code')" class="spaced">
        <Input
          v-model="code"
          placeholder="WT7K-4M2P-9XQD-R3FV-8HLN-2JWC"
          autocapitalize="characters"
          spellcheck="false"
          class="code-field"
          mono
        />
      </Field>
      <i18n-t
        v-if="status?.recovery.length"
        keypath="MasterPasswordDialog.storedCodes"
        tag="p"
        class="hint"
      >
        <template #labels>
          <code>{{ status.recovery.map((row) => row.label).join(", ") }}</code>
        </template>
      </i18n-t>

      <Field :label="t('MasterPasswordDialog.newMasterPassword')" class="spaced">
        <PasswordInput v-model="password" autocomplete="new-password" />
      </Field>
      <Field
        :label="t('MasterPasswordDialog.repeat')"
        class="spaced"
        :error="repeat && !newPasswordOk ? t('MasterPasswordDialog.mismatch') : undefined"
      >
        <PasswordInput v-model="repeat" autocomplete="new-password" />
      </Field>
      <p class="hint">{{ t("MasterPasswordDialog.recoverReplaces") }}</p>
    </template>

    <!-- Change: the same as "forgot", only with the old password. -->
    <template v-else-if="step === 'change'">
      <p class="hint">{{ t("MasterPasswordDialog.changeHint") }}</p>

      <Field :label="t('MasterPasswordDialog.currentMasterPassword')" class="spaced">
        <PasswordInput v-model="oldPassword" />
      </Field>
      <Field :label="t('MasterPasswordDialog.newMasterPassword')" class="spaced">
        <PasswordInput v-model="password" autocomplete="new-password" />
      </Field>
      <Field
        :label="t('MasterPasswordDialog.repeat')"
        class="spaced"
        :error="repeat && !newPasswordOk ? t('MasterPasswordDialog.mismatch') : undefined"
      >
        <PasswordInput v-model="repeat" autocomplete="new-password" />
      </Field>
    </template>

    <!-- The codes. Once. -->
    <template v-else-if="step === 'codes'">
      <Alert status="warn" size="sm">
        <i18n-t keypath="MasterPasswordDialog.codesWarning" tag="span">
          <template #onlyNow>
            <strong>{{ t("MasterPasswordDialog.codesWarningOnlyNow") }}</strong>
          </template>
        </i18n-t>
      </Alert>

      <!--
        Without numbering: the codes are equivalent and are not used up in
        order. A "1." in front would suggest an order that does not exist — and
        when copying them by hand, every digit that is not part of the code is
        one too many.
      -->
      <div class="codes">
        <IconButton
          class="copy"
          variant="text"
          size="sm"
          :icon="copied ? Check : Copy"
          :color="copied ? 'primary' : undefined"
          :label="copied ? t('MasterPasswordDialog.copied') : t('MasterPasswordDialog.copyAll')"
          :title="copied ? t('MasterPasswordDialog.copied') : t('MasterPasswordDialog.copyAll')"
          @click="copyCodes"
        />

        <ul>
          <li v-for="entry in codes" :key="entry">{{ entry }}</li>
        </ul>
      </div>

      <Checkbox v-model:checked="written" class="choice">
        {{ t("MasterPasswordDialog.codesStored") }}
      </Checkbox>
    </template>

    <Alert v-if="error" status="danger" size="sm" class="note">{{ error }}</Alert>

    <!--
      Why it takes a while, while it does. Nine Argon2id runs over 64 MiB each
      are not a click, and a button that simply does nothing for a second looks
      like one whose click did not arrive.
    -->
    <p v-if="busy && makesCodes" class="working-note">
      <Spinner size="sm" class="working-spinner" />
      <span>{{ t("MasterPasswordDialog.working") }}</span>
    </p>

    <!--
      In the text and not in the footer, for the same reason as in the sign-in
      dialog: "Forgot master password" is long, and two more buttons would sit
      next to it. That does not fit into a dialog this wide.
    -->
    <p v-if="step === 'unlock'" class="switch">
      <Button variant="link" size="sm" :disabled="busy" @click="step = 'recover'">
        {{ t("MasterPasswordDialog.forgot") }}
      </Button>
    </p>
    <p v-else-if="step === 'recover'" class="switch">
      <Button variant="link" size="sm" :disabled="busy" @click="step = 'unlock'">
        {{ t("MasterPasswordDialog.backToMaster") }}
      </Button>
    </p>

    <template #actions>
      <span class="spacer"></span>
      <Button v-if="step !== 'codes'" variant="outline" :disabled="busy" @click="emit('cancel')">
        {{ t("common.cancel") }}
      </Button>
      <!--
        While working `loading` instead of `disabled`: the button is blocked,
        but not "unavailable" — it is doing exactly what it was pressed for, and
        a greyed-out spinner looks as if it were stuck.
      -->
      <Button :disabled="!valid && !busy" :loading="busy" @click="submit">
        {{ confirmLabel }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.who {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
}

.who .muted {
  color: var(--muted);
}

.spaced {
  margin-top: 0.75rem;
}

/* The font comes through `mono`; the letter spacing for copying by hand is not there. */
.code-field :deep(input) {
  letter-spacing: 0.05em;
}

.hint {
  margin: 0.4rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.hint code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.9em;
  color: var(--fg);
}

.note {
  margin-top: 0.6rem;
}

/*
  Single column and in a monospace font: the codes are copied by hand, and
  for that it matters that a line is a line.
*/
.codes {
  position: relative;
  margin: 0.75rem 0;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--card);
  user-select: text;
}

.codes ul {
  margin: 0;
  padding: 0;
  list-style: none;
  font-family: Consolas, Menlo, monospace;
  font-size: 0.95rem;
  line-height: 1.9;
  letter-spacing: 0.06em;
}

/*
  Top right in the box instead of below it: it belongs to the codes and not to
  the row of steps. Enough space to the right that it covers no line — the
  codes are narrower than the box.
*/
.codes .copy {
  position: absolute;
  top: 0.4rem;
  right: 0.4rem;
}

/* The note while computing — spinner on the left, sentence next to it. */
.working-note {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  margin: 0.75rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.working-spinner {
  flex: 0 0 auto;
  margin-top: 0.15rem;
}

.choice {
  align-items: flex-start;
  margin-top: 0.75rem;
  font-size: 0.85rem;
}

.switch {
  margin: 0.75rem 0 0;
}

.spacer {
  flex: 1;
}
</style>
