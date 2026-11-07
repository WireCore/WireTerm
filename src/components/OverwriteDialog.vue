<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, SegmentedControl, SegmentedControlItem } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import FileIcon from "./FileIcon.vue";
import FolderIcon from "./FolderIcon.vue";
import { formatBytes, formatDate } from "../sftp";
import type { OverwriteAction, OverwriteAnswer, OverwriteConflict } from "../types";

/**
 * What to do about the names at the target that are already taken.
 *
 * One row per conflict, each with its own answer, and a header that sets every
 * row at once. Asking file by file is right for a handful of names and
 * unusable for the hundred a dragged folder can contain; one choice for the
 * whole batch is the other way round. The header is how the same dialog serves
 * both, and it is why it no longer tries to guess which case it is in.
 *
 * "Only if newer" is not a fourth answer but a way of filling the rows in:
 * every file whose source is newer than what is there is set to replace, the
 * rest to skip. Both sides report a modification time, so this is decided here
 * without asking anything further.
 */
const props = defineProps<{
  conflicts: OverwriteConflict[];
  /**
   * Conflicts found inside directories that are being merged, rather than
   * among the names that were dropped. Only the title and the lead sentence
   * differ — the question and the answers are the same.
   */
  nested?: boolean;
  /**
   * Whether a directory meeting a directory would be merged. False for a move,
   * where a rename cannot put one inside another, so "Replace" there means
   * exactly that — the old one goes.
   */
  merge?: boolean;
}>();

const emit = defineEmits<{ answer: [OverwriteAnswer] }>();
const { t } = useI18n();

/**
 * Everything starts on "Replace", which is what the dialog is asking about:
 * these files were dropped somewhere, and replacing is what that means unless
 * the user says otherwise. Nothing is carried out until "Apply".
 */
const actions = ref<Record<string, OverwriteAction>>(
  Object.fromEntries(props.conflicts.map((entry) => [entry.key, "overwrite"])),
);

const CHOICES = computed<{ value: OverwriteAction; label: string; title: string }[]>(() => [
  {
    value: "overwrite",
    label: t("OverwriteDialog.overwrite"),
    title: t("OverwriteDialog.overwriteTitle"),
  },
  { value: "rename", label: t("OverwriteDialog.rename"), title: t("OverwriteDialog.renameTitle") },
  { value: "skip", label: t("OverwriteDialog.skip"), title: t("OverwriteDialog.skipTitle") },
]);

function setAll(action: OverwriteAction) {
  for (const entry of props.conflicts) actions.value[entry.key] = action;
}

/**
 * A source without a time, or one meeting a target without one, cannot be
 * compared and is left to be replaced — which is what would have happened
 * without the button.
 */
function onlyNewer() {
  for (const entry of props.conflicts) {
    const source = entry.modified;
    const target = entry.targetModified;
    const older = source !== null && target !== null && source <= target;
    actions.value[entry.key] = older ? "skip" : "overwrite";
  }
}

/** A directory meeting a directory is merged rather than replaced. */
const mergeable = (entry: OverwriteConflict) =>
  props.merge !== false && entry.isDir && entry.targetIsDir;

const merges = computed(() => props.conflicts.some(mergeable));

function verb(entry: OverwriteConflict, action: OverwriteAction): string {
  const choice = CHOICES.value.find((option) => option.value === action);
  if (action !== "overwrite") return choice ? choice.label : action;
  return mergeable(entry) ? t("OverwriteDialog.merge") : t("OverwriteDialog.overwrite");
}

const kept = computed(
  () => props.conflicts.filter((entry) => actions.value[entry.key] !== "skip").length,
);

const lead = computed(() =>
  t(props.nested ? "OverwriteDialog.leadNested" : "OverwriteDialog.lead", props.conflicts.length),
);
</script>

<template>
  <!--
    No `@save`: as with the host-key question there is no single default action
    to give Enter. A decision that can overwrite files comes from a click.
  -->
  <EditDialog
    wide
    :title="nested ? t('OverwriteDialog.titleNested') : t('OverwriteDialog.title')"
    @cancel="emit('answer', null)"
  >
    <p class="lead">{{ lead }}</p>

    <div class="bulk">
      <span class="bulk-label">{{ t("OverwriteDialog.all") }}</span>
      <Button
        v-for="choice in CHOICES"
        :key="choice.value"
        variant="outline"
        size="xs"
        :title="choice.title"
        @click="setAll(choice.value)"
      >
        {{ choice.value === "overwrite" && merges ? t("OverwriteDialog.merge") : choice.label }}
      </Button>
      <Button
        variant="outline"
        size="xs"
        :title="t('OverwriteDialog.onlyNewerTitle')"
        @click="onlyNewer"
      >
        {{ t("OverwriteDialog.onlyNewer") }}
      </Button>
    </div>

    <ul class="list">
      <li
        v-for="entry in conflicts"
        :key="entry.key"
        :class="{ off: actions[entry.key] === 'skip' }"
      >
        <span class="what" :title="entry.label">
          <FolderIcon v-if="entry.isDir" :size="13" />
          <FileIcon v-else :size="13" />
          <span class="label">{{ entry.label }}</span>
        </span>

        <!-- What is coming on the left of the arrow, what is already there on
             the right: the direction the transfer itself goes in. -->
        <span class="sizes">
          <span v-if="!entry.isDir">
            {{ formatBytes(entry.size) }}, {{ formatDate(entry.modified) }}
          </span>
          <span v-else class="muted">{{ t("OverwriteDialog.folder") }}</span>
          <span class="arrow">→</span>
          <span v-if="!entry.targetIsDir">
            {{ formatBytes(entry.targetSize) }}, {{ formatDate(entry.targetModified) }}
          </span>
          <span v-else class="muted">{{ t("OverwriteDialog.folder") }}</span>
        </span>

        <SegmentedControl
          class="choice"
          size="sm"
          :label="entry.label"
          v-model="actions[entry.key]"
          required
        >
          <SegmentedControlItem
            v-for="choice in CHOICES"
            :key="choice.value"
            :value="choice.value"
            :title="choice.title"
          >
            {{ verb(entry, choice.value) }}
          </SegmentedControlItem>
        </SegmentedControl>
      </li>
    </ul>

    <template #actions>
      <span class="count">{{
        t("OverwriteDialog.count", { kept, total: conflicts.length })
      }}</span>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('answer', null)">{{ t("common.cancel") }}</Button>
      <Button @click="emit('answer', { ...actions })">{{ t("OverwriteDialog.apply") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.lead {
  margin: 0 0 0.5rem;
}

.bulk {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-bottom: 0.5rem;
}

.bulk-label {
  font-size: 0.8rem;
  color: var(--muted);
}

.list {
  margin: 0;
  padding: 0;
  list-style: none;
  /* Tall enough that a handful needs no scrolling, capped so that a hundred
     does not push the buttons off the screen. */
  max-height: 17rem;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 6px;
}

.list li {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.3em 0.6em;
  font-size: 0.85rem;
  border-bottom: 1px solid var(--border);
}

.list li:last-child {
  border-bottom: none;
}

/* A skipped row stays readable but stops looking like part of the transfer. */
.list li.off .what,
.list li.off .sizes {
  opacity: 0.45;
}

.what {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex: 1 1 auto;
  min-width: 0;
}

/* Cut at the front rather than the end: a nested conflict is told apart by
   its file name, not by the folder every row shares. */
.label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  direction: rtl;
  text-align: left;
}

.sizes {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex: 0 0 auto;
  font-size: 0.78rem;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
}

.arrow {
  opacity: 0.6;
}

.choice {
  flex: 0 0 auto;
}

.count {
  font-size: 0.8rem;
  color: var(--muted);
}

.muted {
  color: var(--muted);
}

.spacer {
  flex: 1;
}
</style>
