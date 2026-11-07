<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Button, Field, Select, Spinner } from "@wirecore/wirelayer-vue";
import { reportVaultProblem } from "../vault";
import type { OpField, OpItem, OpVault, VaultProvider } from "../types";

/**
 * Vault, entry, field — and the reference that points at the field.
 *
 * One picker for both managers: the backend answers "which vaults, which
 * entries, which fields" in the same shape whichever one was asked, so the
 * only thing that travels with each call is the name of the provider.
 *
 * Mounted only while it is open, so opening it is what loads the vaults.
 */
const props = defineProps<{
  provider: VaultProvider;
  /**
   * Looking for an SSH private key: key entries go first, and 1Password is
   * asked for the OpenSSH format.
   */
  wantsKey?: boolean;
  /** Which field to preselect once an entry is chosen. */
  prefer: (field: OpField) => boolean;
}>();

const emit = defineEmits<{ pick: [reference: string] }>();
const { t } = useI18n();

const vaults = ref<OpVault[]>([]);
const items = ref<OpItem[]>([]);
const fields = ref<OpField[]>([]);
const vaultId = ref("");
const itemId = ref("");
const fieldId = ref("");
const busy = ref(false);
const error = ref("");

async function withVault<T>(fn: () => Promise<T>): Promise<T | undefined> {
  busy.value = true;
  error.value = "";
  try {
    return await fn();
  } catch (e) {
    // A missing account or a locked vault is a question, not a message: the
    // dialog it raises is the only place it can be answered, so it takes the
    // place of the error line here.
    error.value = reportVaultProblem(String(e)) ? "" : String(e);
  } finally {
    busy.value = false;
  }
}

async function loadVaults() {
  const result = await withVault(() =>
    invoke<OpVault[]>("vault_vaults", { provider: props.provider }),
  );
  if (result) vaults.value = result.sort((a, b) => a.title.localeCompare(b.title));
}

onMounted(loadVaults);

/**
 * Switching the manager invalidates every list below it, ids included — an
 * entry id from one vault means nothing in the other.
 */
watch(
  () => props.provider,
  () => {
    vaults.value = [];
    vaultId.value = "";
    loadVaults();
  },
);

watch(vaultId, async (id) => {
  items.value = [];
  fields.value = [];
  itemId.value = "";
  fieldId.value = "";
  if (!id) return;
  const result = await withVault(() =>
    invoke<OpItem[]>("vault_items", { provider: props.provider, vaultId: id }),
  );
  if (result) {
    // SSH keys first where one is being looked for; other categories can still
    // hold a key in a text field.
    items.value = props.wantsKey
      ? result.sort(
          (a, b) =>
            Number(b.category === "SshKey") - Number(a.category === "SshKey") ||
            a.title.localeCompare(b.title),
        )
      : result.sort((a, b) => a.title.localeCompare(b.title));
  }
});

watch(itemId, async (id) => {
  fields.value = [];
  fieldId.value = "";
  if (!id || !vaultId.value) return;
  const result = await withVault(() =>
    invoke<OpField[]>("vault_fields", {
      provider: props.provider,
      vaultId: vaultId.value,
      itemId: id,
    }),
  );
  if (result) {
    fields.value = result;
    // Almost always the only sensible choice, so preselect it.
    fieldId.value = result.find(props.prefer)?.id ?? result[0]?.id ?? "";
  }
});

/**
 * Built from ids where the manager has them, so renaming an entry does not
 * break a stored connection. Bitwarden's built-in fields have no ids and are
 * named instead — see `field_list` in src-tauri/src/bitwarden/mod.rs.
 *
 * `ssh-format=openssh` is 1Password's and required there for a key: without it
 * it hands out PKCS#8, which an SSH client cannot use. It is wrong on any other
 * field, and meaningless to Bitwarden, which stores an SSH key in the format it
 * was given.
 */
const reference = computed(() => {
  if (!vaultId.value || !itemId.value || !fieldId.value) return "";
  const scheme = props.provider === "bitwarden" ? "bw" : "op";
  const base = `${scheme}://${vaultId.value}/${itemId.value}/${fieldId.value}`;
  return props.wantsKey && props.provider === "onePassword"
    ? `${base}?ssh-format=openssh`
    : base;
});

const vaultOptions = computed(() =>
  vaults.value.map((v) => ({ value: v.id, label: `${v.title} (${v.itemCount})` })),
);
const itemOptions = computed(() =>
  items.value.map((i) => ({ value: i.id, label: `${i.title} [${i.category}]` })),
);
const fieldOptions = computed(() =>
  fields.value.map((f) => ({ value: f.id, label: `${f.title} (${f.fieldType})` })),
);
</script>

<template>
  <div class="picker">
    <!--
      `stop-key-propagation`: the dialog around it listens for Enter and Escape
      on the window, and they would otherwise save or close the whole form
      instead of picking an entry or closing the list. "" is "nothing chosen".
    -->
    <Field :label="t('VaultPicker.vault')">
      <Select
        v-model="vaultId"
        empty-value=""
        :items="vaultOptions"
        :disabled="busy"
        filter
        stop-key-propagation
        :placeholder="t('VaultPicker.choose')"
        :empty-text="t('VaultPicker.nothingFound')"
      />
    </Field>

    <Field :label="t('VaultPicker.item')">
      <Select
        v-model="itemId"
        empty-value=""
        :items="itemOptions"
        :disabled="busy || !items.length"
        filter
        stop-key-propagation
        :placeholder="t('VaultPicker.choose')"
        :empty-text="t('VaultPicker.nothingFound')"
      />
    </Field>

    <Field :label="t('VaultPicker.field')">
      <Select
        v-model="fieldId"
        empty-value=""
        :items="fieldOptions"
        :disabled="busy || !fields.length"
        filter
        stop-key-propagation
        :placeholder="t('VaultPicker.choose')"
        :empty-text="t('VaultPicker.nothingFound')"
      />
    </Field>

    <p v-if="busy" class="hint"><Spinner size="sm" />{{ t("VaultPicker.loading") }}</p>
    <Alert v-if="error" status="danger" size="sm" class="error">{{ error }}</Alert>

    <div v-if="reference" class="apply">
      <code>{{ reference }}</code>
      <Button @click="emit('pick', reference)">{{ t("VaultPicker.apply") }}</Button>
    </div>
  </div>
</template>

<style scoped>
.picker {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding-top: 0.75rem;
}

.hint {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  margin: 0;
  font-size: 0.85rem;
  color: var(--muted);
}

.error {
  word-break: break-word;
}

.apply {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.apply code {
  flex: 1;
  min-width: 0;
  font-size: 0.75rem;
  padding: 0.35em 0.5em;
  border-radius: 6px;
  background: var(--card);
  word-break: break-all;
}
</style>
