<script setup lang="ts">
/**
 * Who may access a project.
 *
 * A share points at a team or at the whole organization and grants "Edit" or
 * "Read only". It controls which *rows* someone gets — owners and
 * administrators see everything anyway, members only what is shared.
 *
 * What it does **not** control: nobody gets at the secrets through a share
 * alone. For that a client has to wrap the project key for them, and that
 * happens on its own at the next sync — the note below says so, because
 * otherwise it looks as if the share had no effect.
 *
 * The **whole set** is saved: whoever is no longer in the list loses access,
 * and the server deletes their wrapped copy of the project key along the way.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Card, NativeSelect } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import {
  members as loadMembers,
  rotateProjectKey,
  setShares,
  shares as loadShares,
  type Rotated,
} from "../cloud";
import { SHARE_ROLE_LABELS, type ShareRole } from "../types";

const props = defineProps<{
  workspaceId: string;
  projectId: string;
  projectName: string;
}>();

const emit = defineEmits<{ saved: []; cancel: [] }>();
const { t } = useI18n();

/** `null` as `teamId` means: the whole organization. */
type Entry = { teamId: string | null; name: string; role: ShareRole | "" };

const entries = ref<Entry[]>([]);
const busy = ref(true);
const error = ref("");

const ROLES: ShareRole[] = ["editor", "viewer"];
const roleItems = computed(() =>
  ROLES.map((role) => ({ value: role, label: SHARE_ROLE_LABELS[role] })),
);

const granted = computed(() => entries.value.filter((entry) => entry.role !== ""));

/** What was shared when opened — to see whether someone is being dropped right now. */
const before = ref<Map<string | null, ShareRole | "">>(new Map());
const removing = computed(() =>
  entries.value.some((entry) => before.value.get(entry.teamId) && entry.role === ""),
);
const dirty = computed(() => entries.value.some((entry) => before.value.get(entry.teamId) !== entry.role));

const rotated = ref<Rotated | null>(null);

/**
 * Save first, then renew: whoever is being taken out right now must not get
 * the new version wrapped for them.
 */
async function rotate() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    if (dirty.value) {
      await setShares(
        props.workspaceId,
        props.projectId,
        granted.value.map((entry) => ({ teamId: entry.teamId, role: entry.role as ShareRole })),
      );
      before.value = new Map(entries.value.map((entry) => [entry.teamId, entry.role]));
    }
    rotated.value = await rotateProjectKey(props.workspaceId, props.projectId);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  try {
    const [current, org] = await Promise.all([
      loadShares(props.workspaceId, props.projectId),
      loadMembers(props.workspaceId),
    ]);

    const roleOf = (teamId: string | null): ShareRole | "" =>
      current.find((share) => (share.teamId ?? null) === teamId)?.role ?? "";

    entries.value = [
      { teamId: null, name: t("SharesDialog.wholeOrganization"), role: roleOf(null) },
      ...org.teams.map((team) => ({
        teamId: team.id,
        name: team.name,
        role: roleOf(team.id),
      })),
    ];
    before.value = new Map(entries.value.map((entry) => [entry.teamId, entry.role]));
    error.value = "";
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
});

async function save() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    await setShares(
      props.workspaceId,
      props.projectId,
      granted.value.map((entry) => ({ teamId: entry.teamId, role: entry.role as ShareRole })),
    );
    emit("saved");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog
:title="t('SharesDialog.title', { name: projectName })"
    :can-save="!busy"
    @save="save"
    @cancel="emit('cancel')"
  >
    <p class="hint">{{ t("SharesDialog.hint") }}</p>

    <ul v-if="entries.length" class="rows">
      <Card v-for="entry in entries" :key="entry.teamId ?? 'org'" size="sm" as-child>
        <li class="row">
          <span class="grow" :class="{ everyone: entry.teamId === null }">{{ entry.name }}</span>
          <NativeSelect
            v-model="entry.role"
            class="select"
            size="sm"
            :items="roleItems"
            :placeholder="t('SharesDialog.none')"
            :disabled="busy"
            :aria-label="t('SharesDialog.shareFor', { name: entry.name })"
          />
        </li>
      </Card>
    </ul>
    <p v-else-if="!busy" class="hint">{{ t("SharesDialog.noTeams") }}</p>

    <p class="hint">{{ t("SharesDialog.newMember") }}</p>

    <section class="rotate">
      <h4>{{ t("SharesDialog.rotateTitle") }}</h4>
      <p class="hint">{{ t("SharesDialog.rotateHint") }}</p>
      <Alert v-if="removing && !rotated" status="warn" size="sm">
        {{ t("SharesDialog.removingWarning") }}
      </Alert>
      <Alert v-if="rotated" status="success" size="sm">
        {{ t("SharesDialog.rotated", { secrets: rotated.secrets, n: rotated.granted }, rotated.granted) }}
        <template v-if="rotated.waiting">
          {{ t("SharesDialog.rotatedWaiting", { n: rotated.waiting }) }}
        </template>
        <template v-if="rotated.skipped">
          {{ t("SharesDialog.rotatedSkipped", { n: rotated.skipped }) }}
        </template>
      </Alert>
      <Button variant="outline" :disabled="busy" @click="rotate">
        {{ dirty ? t("SharesDialog.saveAndRotate") : t("SharesDialog.rotate") }}
      </Button>
    </section>

    <Alert v-if="error" class="error" status="danger" size="sm">{{ error }}</Alert>
  </EditDialog>
</template>

<style scoped>
.rotate {
  margin-top: 1.25rem;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.5rem;
}

.rotate h4 {
  margin: 0;
}

.hint {
  margin: 0.6rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.error {
  margin-top: 0.75rem;
}

.rows {
  list-style: none;
  margin: 0.75rem 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

/* Border, surface and radius come from the Card (sm); here only what a row needs. */
.row {
  flex-direction: row;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.65rem;
  font-size: 0.9rem;
}

.grow {
  flex: 1;
  min-width: 0;
}

.select {
  flex: 0 0 auto;
  width: auto;
}

.everyone {
  font-style: italic;
}
</style>
