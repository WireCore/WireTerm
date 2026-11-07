<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Field, Input } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { defaultBitwardenAccount, VAULT_LABELS, type VaultProvider, type Workspace } from "../types";

/**
 * Asked when a vault turns out to have no usable account — none was ever
 * given, or the one on file is not one this machine can use.
 *
 * The answer is saved onto the workspace rather than onto the device: which
 * account a set of connections is read with belongs with the connections. It
 * stays per user all the same, because a workspace is not shared yet.
 *
 * One dialog for both managers, because it is one question — "which
 * access?" — and only the fields it takes differ.
 */
const props = defineProps<{
  workspace: Workspace;
  provider: VaultProvider;
  reason: string;
}>();

const emit = defineEmits<{ save: [values: Partial<Workspace>]; cancel: [] }>();
const { t } = useI18n();

/** Prefilled and selected: the usual reason to be here is a typo in it. */
const account = ref(props.workspace.onePasswordAccount ?? "");
const bitwarden = ref({ ...defaultBitwardenAccount(), ...props.workspace.bitwarden });

const label = computed(() => VAULT_LABELS[props.provider]);

const valid = computed(() =>
  props.provider === "onePassword"
    ? account.value.trim().length > 0
    : bitwarden.value.email.trim().length > 0,
);

function save() {
  if (!valid.value) return;
  emit(
    "save",
    props.provider === "onePassword"
      ? { onePasswordAccount: account.value.trim() }
      : {
          bitwarden: {
            server: bitwarden.value.server.trim(),
            email: bitwarden.value.email.trim(),
            acceptInvalidCert: bitwarden.value.acceptInvalidCert,
          },
        },
  );
}
</script>

<template>
  <EditDialog :title="t('VaultAccountDialog.title', { provider: label })" @save="save" @cancel="emit('cancel')">
    <p class="reason">{{ reason }}</p>

    <template v-if="provider === 'onePassword'">
      <Field :label="t('VaultAccountDialog.accountFor', { name: workspace.name })">
        <Input
          v-model="account"
          :placeholder="t('VaultAccountDialog.accountPlaceholder')"
          data-autoselect
        />
      </Field>

      <p class="hint">{{ t("VaultAccountDialog.onePasswordHint") }}</p>
    </template>

    <template v-else>
      <Field :label="t('VaultAccountDialog.emailFor', { name: workspace.name })">
        <Input
          v-model="bitwarden.email"
          :placeholder="t('VaultAccountDialog.emailPlaceholder')"
          data-autoselect
        />
      </Field>

      <Field :label="t('VaultAccountDialog.server')" class="spaced">
        <Input v-model="bitwarden.server" :placeholder="t('VaultAccountDialog.serverPlaceholder')" />
      </Field>

      <i18n-t keypath="VaultAccountDialog.bitwardenHint" tag="p" class="hint">
        <template #example>
          <code>{{ t("VaultAccountDialog.serverExample") }}</code>
        </template>
      </i18n-t>
    </template>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('cancel')">{{ t("common.cancel") }}</Button>
      <Button :disabled="!valid" @click="save">{{ t("common.save") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.reason {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--warn);
}

.spaced {
  margin-top: 0.75rem;
}

.hint {
  margin: 0.75rem 0 0;
  font-size: 0.85rem;
  line-height: 1.5;
  color: var(--muted);
}

.hint code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.9em;
  color: var(--fg);
  word-break: break-all;
}

.spacer {
  flex: 1;
}
</style>
