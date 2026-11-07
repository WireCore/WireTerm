<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Checkbox } from "@wirecore/wirelayer-vue";
import { ChevronDown, ChevronRight } from "@lucide/vue";
import EditDialog from "./EditDialog.vue";
import { bitsFromMode, modeFromBits, type PermissionBits } from "../types";

/**
 * "Change permissions" — a chmod dialog.
 *
 * Works on the raw bits rather than the `rwxr-xr-x` string the pane shows:
 * that string cannot say setuid, setgid or sticky, and a dialog that changes
 * permissions has to be able to set the ones it can also show.
 */
const props = defineProps<{
  name: string;
  isDir: boolean;
  /** null where the server never reported one; treated as all bits unset. */
  mode: number | null;
}>();

const emit = defineEmits<{ save: [mode: number, recursive: boolean]; stop: []; cancel: [] }>();
const { t } = useI18n();

const bits = ref<PermissionBits>(bitsFromMode(props.mode ?? 0));

/**
 * "Also apply to contents" — directories only, and off to begin with:
 * a recursive chmod touches files nobody named and cannot be undone.
 */
const recursive = ref(false);

const busy = ref(false);

/** While it runs, "Cancel" stops the run instead of closing the dialog. */
function stopOrClose() {
  if (busy.value) emit("stop");
  else emit("cancel");
}

const ROWS = computed<{ label: string; read: keyof PermissionBits; write: keyof PermissionBits; exec: keyof PermissionBits }[]>(() => [
  { label: t("PermissionsDialog.owner"), read: "ownerRead", write: "ownerWrite", exec: "ownerExec" },
  { label: t("PermissionsDialog.group"), read: "groupRead", write: "groupWrite", exec: "groupExec" },
  { label: t("PermissionsDialog.other"), read: "otherRead", write: "otherWrite", exec: "otherExec" },
]);

const mode = computed(() => modeFromBits(bits.value));
const octal = computed(() => mode.value.toString(8).padStart(3, "0"));

/**
 * What a file inside a recursively changed directory gets, spelled out because
 * it is deliberately not what is set above.
 *
 * `755` applied to a whole tree would make every `.php` in it executable,
 * which is the classic way a recursive chmod ruins a deployment. Files
 * therefore lose the execute bits unless they already carry one — `chmod`'s
 * own `a+X` rule, and what anyone setting `rwxr-xr-x` on a folder means. The
 * backend applies it; this only says so.
 */
const fileOctal = computed(() => (mode.value & ~0o111).toString(8).padStart(3, "0"));

function apply() {
  // A recursive run can take a while on a large tree, and a dialog that stays
  // put with live buttons invites a second click that starts it over.
  busy.value = true;
  emit("save", mode.value, props.isDir && recursive.value);
}

/** The advanced bits read oddly as checkboxes without saying what they are. */
const ADVANCED = computed<{ label: string; key: keyof PermissionBits; hint: string }[]>(() => [
  {
    label: "Setuid",
    key: "setuid",
    hint: t("PermissionsDialog.setuidHint"),
  },
  {
    label: "Setgid",
    key: "setgid",
    hint: t("PermissionsDialog.setgidHint"),
  },
  {
    label: t("PermissionsDialog.sticky"),
    key: "sticky",
    hint: t("PermissionsDialog.stickyHint"),
  },
]);

const advancedSet = computed(() => bits.value.setuid || bits.value.setgid || bits.value.sticky);
const showAdvanced = ref(advancedSet.value);
</script>

<template>
  <EditDialog :title="t('PermissionsDialog.title', { name })" @save="apply" @cancel="stopOrClose">
    <table class="grid">
      <thead>
        <tr>
          <th></th>
          <th>{{ t("PermissionsDialog.read") }}</th>
          <th>{{ t("PermissionsDialog.write") }}</th>
          <th>{{ isDir ? t("PermissionsDialog.executeOpen") : t("PermissionsDialog.execute") }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in ROWS" :key="row.label">
          <th>{{ row.label }}</th>
          <td>
            <Checkbox
              v-model:checked="bits[row.read]"
              :aria-label="t('PermissionsDialog.cell', { who: row.label, what: t('PermissionsDialog.read') })"
            />
          </td>
          <td>
            <Checkbox
              v-model:checked="bits[row.write]"
              :aria-label="t('PermissionsDialog.cell', { who: row.label, what: t('PermissionsDialog.write') })"
            />
          </td>
          <td>
            <Checkbox
              v-model:checked="bits[row.exec]"
              :aria-label="t('PermissionsDialog.cell', { who: row.label, what: t('PermissionsDialog.execute') })"
            />
          </td>
        </tr>
      </tbody>
    </table>

    <Button
      class="advanced-toggle"
      variant="text"
      size="sm"
      :leading-icon="showAdvanced ? ChevronDown : ChevronRight"
      :aria-expanded="showAdvanced"
      @click="showAdvanced = !showAdvanced"
    >
      {{ t("PermissionsDialog.advanced") }}
    </Button>

    <div v-if="showAdvanced" class="advanced">
      <Checkbox
        v-for="item in ADVANCED"
        :key="item.key"
        v-model:checked="bits[item.key]"
        class="advanced-row"
      >
        <span class="text">
          <strong>{{ item.label }}</strong>
          <span class="hint">{{ item.hint }}</span>
        </span>
      </Checkbox>
    </div>

    <p class="octal">
      {{ t("PermissionsDialog.octal") }} <span class="mono">{{ octal }}</span>
    </p>

    <!-- Directories only: there is nothing inside a file to apply this to. -->
    <div v-if="isDir" class="recursive">
      <Checkbox v-model:checked="recursive" class="advanced-row">
        <span class="text">
          <strong>{{ t("PermissionsDialog.recursive") }}</strong>
          <i18n-t keypath="PermissionsDialog.recursiveHint" tag="span" class="hint">
            <template #folders>
              <span class="mono">{{ octal }}</span>
            </template>
            <template #files>
              <span class="mono">{{ fileOctal }}</span>
            </template>
          </i18n-t>
        </span>
      </Checkbox>
    </div>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" @click="stopOrClose">{{ t("common.cancel") }}</Button>
      <Button :disabled="busy" @click="apply">
        {{ busy ? t("PermissionsDialog.running") : t("PermissionsDialog.apply") }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.grid {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

.grid th,
.grid td {
  padding: 0.35em 0.5em;
  text-align: center;
}

.grid thead th {
  color: var(--muted);
  font-weight: 500;
  font-size: 0.78rem;
}

.grid tbody th {
  text-align: left;
  font-weight: 500;
}

.advanced-toggle {
  margin-top: 0.75rem;
}

.advanced {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: 0.4rem;
  padding: 0.6rem;
  border-radius: 6px;
  background: var(--bg);
  border: 1px solid var(--border);
}

.advanced-row {
  align-items: flex-start;
  font-size: 0.85rem;
}

.advanced-row .text {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.advanced-row .hint {
  font-size: 0.75rem;
  color: var(--muted);
}

.octal {
  margin: 0.75rem 0 0;
  font-size: 0.85rem;
  color: var(--muted);
}

.recursive {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid var(--border);
}

.recursive .hint {
  line-height: 1.45;
}

.mono {
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  color: var(--fg);
}

.spacer {
  flex: 1;
}
</style>
