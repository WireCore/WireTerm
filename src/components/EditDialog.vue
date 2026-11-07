<script lang="ts">
import { ref as globalRef } from "vue";

/**
 * The dialogs currently open, deepest last.
 *
 * Only the top one answers the keyboard. Two can be on screen at once — a
 * host-key question raised by a connection test runs in front of the form that
 * started it — and Escape must close the one being looked at, not both.
 */
const stack: symbol[] = [];

/**
 * How many dialogs are open, as a reactive number.
 *
 * Needed by the sync: it swaps the tree for the server's state, and a form
 * holds a connection from the old one. Swapping in the middle of an input
 * would mean that "Save" writes into something that no longer exists. The
 * sync runs anyway — it is only put in place later.
 */
export const dialogsOpen = globalRef(0);
</script>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button, Dialog, DialogContent } from "@wirecore/wirelayer-vue";

/**
 * The shell every edit dialog shares: title, a scrolling body for the fields,
 * and the buttons. It owns nothing but the two-stage delete and the keyboard —
 * the draft and what "Save" means belong to whoever fills the slot.
 */
const props = withDefaults(defineProps<{
  title: string;
  /**
   * "create" leaves out Delete and labels the confirm button "Create".
   * Omitted along with the buttons themselves, when a dialog brings its own.
   */
  mode?: "create" | "edit";
  /** Greys out the confirm button while the draft is incomplete. */
  canSave?: boolean;
  /** Asked in place of the buttons once Delete is pressed. */
  deleteQuestion?: string;
  /**
   * Takes "Delete" out of an `edit` dialog.
   *
   * For what cannot be deleted — the personal workspace, for instance — and
   * for where "delete" has more than one meaning: there the options are in
   * the form, named, instead of behind one word.
   */
  canDelete?: boolean;
  /** Roomier, for forms with more than a field or two. */
  wide?: boolean;
  /** A width of its own (CSS length), for content that needs more than `wide`. */
  width?: string;
  /**
   * Without a footer, for content with buttons of its own (the wizard).
   * Cancelling then goes through the cross at the top and Escape.
   */
  footer?: boolean;
}>(), {
  // Without a default Vue would turn a missing boolean prop into `false`.
  canDelete: true,
  footer: true,
});

const emit = defineEmits<{ save: []; remove: []; cancel: [] }>();
const { t } = useI18n();

const content = ref<InstanceType<typeof DialogContent>>();

/** For content that changes while open: focuses its first field again. */
defineExpose({ focusFirst: () => content.value?.focusFirst() });

const confirmingDelete = ref(false);

/** This dialog's place in [`stack`]. */
const token = Symbol("dialog");

/**
 * Enter confirms, Escape cancels — from anywhere in the dialog, not only from
 * the field that happens to have focus.
 *
 * On the window rather than on the overlay, because a dialog that only asks a
 * question has nothing focusable in it at all, and Escape has to work there
 * too.
 */
function onKeydown(event: KeyboardEvent) {
  if (stack[stack.length - 1] !== token) return;

  if (event.key === "Escape") {
    // Backs out of the delete question rather than out of the dialog: the
    // question was asked because the answer matters, and leaving the form open
    // is the harmless half of it.
    if (confirmingDelete.value) confirmingDelete.value = false;
    else emit("cancel");
  } else if (event.key === "Enter") {
    if (event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) return;
    const target = event.target as HTMLElement | null;
    // A textarea takes the key itself, and Enter on a focused button already
    // means that button.
    if (target?.tagName === "TEXTAREA" || target?.tagName === "BUTTON") return;
    // Nothing while the delete question stands: that is the one answer worth
    // a deliberate click.
    if (confirmingDelete.value || props.canSave === false) return;
    emit("save");
  } else {
    return;
  }
  event.preventDefault();
}

/** The close button in the header: the same as Cancel. */
function onOpenChange(open: boolean) {
  if (!open) emit("cancel");
}

onMounted(() => {
  stack.push(token);
  dialogsOpen.value += 1;
  window.addEventListener("keydown", onKeydown);
});

onBeforeUnmount(() => {
  const at = stack.indexOf(token);
  if (at >= 0) stack.splice(at, 1);
  dialogsOpen.value = Math.max(0, dialogsOpen.value - 1);
  window.removeEventListener("keydown", onKeydown);
});
</script>

<template>
  <!--
    No click-away close — a stray click must not throw the input away. Escape
    does that, and it is handled on the window (see onKeydown), so the delete
    question can take it first.
  -->
  <Dialog
    :open="true"
    :close-on-escape="false"
    :close-on-interact-outside="false"
    @update:open="onOpenChange"
  >
    <DialogContent
      ref="content"
      :title="title"
      title-position="header"
      :size="width ? undefined : wide ? 'lg' : 'md'"
      :style="width ? { '--wc-dialog-w': width } : undefined"
      scroll-behavior="inside"
    >
      <slot />

      <template v-if="footer" #footer>
        <div v-if="confirmingDelete" class="actions">
          <p class="warn">{{ deleteQuestion }}</p>
          <span class="spacer"></span>
          <Button variant="outline" @click="confirmingDelete = false">{{ t("common.cancel") }}</Button>
          <Button variant="danger" @click="emit('remove')">{{ t("common.delete") }}</Button>
        </div>

        <!--
          The draft-and-confirm buttons are the fallback, not the only option:
          a dialog whose changes take effect as they are made wants different
          verbs, and fills the slot instead.
        -->
        <div v-else class="actions">
          <slot name="actions">
            <Button
              v-if="mode === 'edit' && canDelete"
              variant="text"
              color="danger"
              @click="confirmingDelete = true"
            >
              {{ t("common.delete") }}
            </Button>
            <span class="spacer"></span>
            <Button variant="outline" @click="emit('cancel')">{{ t("common.cancel") }}</Button>
            <Button :disabled="!canSave" @click="emit('save')">
              {{ mode === "create" ? t("EditDialog.create") : t("common.save") }}
            </Button>
          </slot>
        </div>
      </template>
    </DialogContent>
  </Dialog>
</template>

<style scoped>
/*
  Wrapping instead of overlapping. The footer is as wide as the dialog, and a
  dialog is 24rem wide — whoever puts one button too many or one too long in
  here gets a second line, not buttons that lie on top of each other and make
  each other unreachable.

  This is a net, not an invitation: a footer with more than three buttons
  should be taken apart, and the side paths belong in the text above it.
*/
.actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  width: 100%;
}

.spacer {
  flex: 1;
}

.warn {
  margin: 0;
  min-width: 0;
  font-size: 0.9rem;
  color: var(--warn);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
