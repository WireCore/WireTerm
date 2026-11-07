<script setup lang="ts">
/**
 * Who belongs to a workspace — members, invitations, teams.
 *
 * Two levels that answer different questions:
 *
 * - The **role** (`owner`, `admin`, `member`) decides who may create, delete
 *   and share projects, and whether someone sees all projects or only the
 *   shared ones.
 * - The **team** is the unit a project is shared with. Without a team there is
 *   only "the whole organization".
 *
 * And a third thing that is neither role nor team: even an owner only gets at
 * the secrets once someone has wrapped the project key for them. No server
 * does that, but a client during sync — that is why "waiting for setup" is
 * shown here instead of a button.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ChevronDown, ChevronRight } from "@lucide/vue";
import {
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  NativeSelect,
} from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import {
  addTeamMember,
  cancelInvitation,
  createTeam,
  invite,
  members as loadMembers,
  removeMember,
  removeTeam,
  rotateProjectKey,
  removeTeamMember,
  renameTeam,
  setMemberRole,
  staleKeys,
  teamMembers,
  type MemberRow,
  type Members,
} from "../cloud";
import { ROLE_LABELS, type Remote, type Role } from "../types";
import { workspaces } from "../store";

const props = defineProps<{ workspaceId: string; workspaceName: string; remote: Remote }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const data = ref<Members | null>(null);
const busy = ref(false);
const error = ref("");

const inviteEmail = ref("");
const inviteRole = ref<Role>("member");
const inviteTeam = ref<string>("");

const newTeam = ref("");
/** Which team is expanded right now, along with its members. */
const openTeam = ref<string | null>(null);
const openTeamMembers = ref<MemberRow[]>([]);
const renaming = ref<{ id: string; name: string } | null>(null);

/**
 * Whether the UI may offer anything at all.
 *
 * The answer comes along from the server — writing the rule down a second time
 * here would mean keeping it right in two places.
 */
const admin = computed(() => props.remote.admin && !data.value?.managedBy);

/** The personal workspace has no member management — but inviting works. */
const personal = computed(() => props.remote.kind === "personal");

const ROLES: Role[] = ["owner", "admin", "member"];
const roleItems = computed(() =>
  ROLES.map((role) => ({ value: role, label: ROLE_LABELS[role] })),
);

const teamItems = computed(() =>
  (data.value?.teams ?? []).map((team) => ({ value: team.id, label: team.name })),
);

/** The public key per user, for "waiting for setup". */
const hasKey = computed(() => {
  const map = new Map<string, boolean>();
  for (const entry of data.value?.keys ?? []) map.set(entry.userId, entry.key !== null);
  return map;
});

onMounted(refresh);

async function refresh() {
  busy.value = true;
  try {
    data.value = await loadMembers(props.workspaceId);
    error.value = "";
    if (openTeam.value) await openTeamDetails(openTeam.value);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

/** Carries out a change and fetches the state again afterwards. */
// ---- After removing: renew keys ------------------------------------------------
//
// Whoever is taken out loses their copies of the project keys — but what they
// have read until then, they still know. It only becomes tight with a new
// version per project. Which projects those are, the server says: the ones
// whose current version they hold without being allowed to see them anymore.

/** Who was just removed — the reason for the offer below. */
const removed = ref<string | null>(null);
/** The projects whose keys they still know. */
const stale = ref<{ id: string; name: string }[]>([]);
const rotating = ref(false);
const rotated = ref<{ name: string; outcome: string; ok: boolean }[]>([]);

async function rotateAll() {
  if (rotating.value) return;
  rotating.value = true;
  rotated.value = [];
  for (const project of stale.value) {
    try {
      const result = await rotateProjectKey(props.workspaceId, project.id);
      rotated.value.push({
        name: project.name,
        ok: result.skipped === 0,
        outcome:
          t("MembersDialog.reencrypted", { n: result.secrets }) +
          (result.skipped ? t("MembersDialog.skipped", { n: result.skipped }) : ""),
      });
    } catch (e) {
      rotated.value.push({ name: project.name, ok: false, outcome: String(e) });
    }
  }
  rotating.value = false;
  removed.value = null;
}

async function removeAndOffer(name: string, userId: string, action: () => Promise<unknown>) {
  await act(async () => {
    await action();
    rotated.value = [];
    const projects = workspaces.find((w) => w.id === props.workspaceId)?.projects ?? [];
    stale.value = (await staleKeys(props.workspaceId, userId)).map((id) => ({
      id,
      name: projects.find((project) => project.id === id)?.name ?? id,
    }));
    removed.value = name;
  });
}

async function act(action: () => Promise<unknown>) {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    await action();
    data.value = await loadMembers(props.workspaceId);
    if (openTeam.value) await openTeamDetails(openTeam.value);
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}

/**
 * The organization's members by user ID.
 *
 * better-auth's `list-team-members` hands out the table's rows and nothing
 * else — a team row only knows a user ID. The name for it is in the member
 * list, which is loaded anyway.
 */
const byUserId = computed(() => {
  const map = new Map<string, MemberRow>();
  for (const row of data.value?.organization.members ?? []) map.set(row.userId, row);
  return map;
});

function label(member: MemberRow): string {
  const known = byUserId.value.get(member.userId) ?? member;
  return known.user?.name?.trim() || known.user?.email || member.userId;
}

async function sendInvite() {
  const email = inviteEmail.value.trim();
  if (!email) return;
  await act(async () => {
    await invite(props.workspaceId, email, inviteRole.value, inviteTeam.value || null);
    inviteEmail.value = "";
  });
}

async function openTeamDetails(teamId: string) {
  openTeam.value = teamId;
  try {
    openTeamMembers.value = await teamMembers(props.workspaceId, teamId);
  } catch (e) {
    openTeamMembers.value = [];
    error.value = String(e);
  }
}

function toggleTeam(teamId: string) {
  if (openTeam.value === teamId) {
    openTeam.value = null;
    openTeamMembers.value = [];
    return;
  }
  void openTeamDetails(teamId);
}

/** Who is not in the expanded team yet. */
const teamCandidates = computed(() => {
  const inside = new Set(openTeamMembers.value.map((row) => row.userId));
  return (data.value?.organization.members ?? []).filter((row) => !inside.has(row.userId));
});
</script>

<template>
  <EditDialog :title="t('MembersDialog.title', { name: workspaceName })" wide @cancel="emit('close')">
    <p class="hint">
      {{
        t("MembersDialog.who", {
          email: remote.email,
          server: remote.server,
          role: ROLE_LABELS[remote.role],
        })
      }}
    </p>

    <Alert v-if="data?.managedBy" status="info" size="sm">
      <i18n-t keypath="MembersDialog.managedBy" tag="span">
        <template #url><code>{{ data.managedBy }}</code></template>
      </i18n-t>
    </Alert>

    <p v-if="personal" class="hint">{{ t("MembersDialog.personal") }}</p>

    <!-- ---- Members --------------------------------------------------- -->
    <h4 class="label-mono">{{ t("MembersDialog.members") }}</h4>
    <ul class="rows">
      <Card v-for="member in data?.organization.members ?? []" :key="member.id" size="sm" as-child>
        <li class="row">
          <span class="grow">
            <span class="name">{{ label(member) }}</span>
            <span v-if="member.user?.email" class="muted">{{ member.user.email }}</span>
            <Badge v-if="hasKey.get(member.userId) === false" variant="warn">
              {{ t("MembersDialog.waitingForSetup") }}
            </Badge>
          </span>

          <NativeSelect
            v-if="admin && member.userId !== data?.ownUserId"
            class="select"
            size="sm"
            :items="roleItems"
            :model-value="member.role"
            :disabled="busy"
            :aria-label="t('MembersDialog.role')"
            @update:model-value="act(() => setMemberRole(workspaceId, member.id, $event))"
          />
          <span v-else class="muted">{{ ROLE_LABELS[member.role] }}</span>

          <Button
            v-if="admin && member.userId !== data?.ownUserId"
            variant="text"
            color="danger"
            size="sm"
            :disabled="busy"
            :title="t('MembersDialog.removeFromWorkspace')"
            @click="removeAndOffer(label(member), member.userId, () => removeMember(workspaceId, member.id))"
          >
            {{ t("common.remove") }}
          </Button>
        </li>
      </Card>
    </ul>
    <p v-if="hasKey.size && [...hasKey.values()].some((value) => !value)" class="hint">
      {{ t("MembersDialog.noKeyHint") }}
    </p>

    <!-- ---- Invitations ----------------------------------------------- -->
    <template v-if="admin">
      <h4 class="label-mono">{{ t("MembersDialog.inviteTitle") }}</h4>
      <Card size="sm" as-child>
        <div class="row">
          <Input
            v-model="inviteEmail"
            class="fill"
            size="sm"
            type="email"
            :placeholder="t('MembersDialog.emailPlaceholder')"
            autocapitalize="off"
            spellcheck="false"
            @keydown.enter.prevent="sendInvite"
          />
          <NativeSelect
            v-model="inviteRole"
            class="select"
            size="sm"
            :items="roleItems"
            :aria-label="t('MembersDialog.role')"
          />
          <NativeSelect
            v-model="inviteTeam"
            class="select"
            size="sm"
            :items="teamItems"
            :placeholder="t('MembersDialog.noTeam')"
            :title="t('MembersDialog.teamOptional')"
          />
          <Button size="sm" :disabled="!inviteEmail.trim() || busy" @click="sendInvite">
            {{ t("MembersDialog.invite") }}
          </Button>
        </div>
      </Card>

      <ul v-if="data?.organization.invitations?.length" class="rows">
        <Card
          v-for="entry in data.organization.invitations.filter((row) => row.status === 'pending')"
          :key="entry.id"
          size="sm"
          as-child
        >
          <li class="row">
            <span class="grow">
              <span class="name">{{ entry.email }}</span>
              <span class="muted">
                {{ t("MembersDialog.invitedAs", { role: entry.role ?? "member" }) }}
              </span>
            </span>
            <Button
              variant="text"
              color="danger"
              size="sm"
              :disabled="busy"
              @click="act(() => cancelInvitation(workspaceId, entry.id))"
            >
              {{ t("MembersDialog.withdraw") }}
            </Button>
          </li>
        </Card>
      </ul>
    </template>

    <!-- ---- Teams ------------------------------------------------------ -->
    <template v-if="admin">
      <h4 class="label-mono">{{ t("MembersDialog.teams") }}</h4>
      <p class="hint">{{ t("MembersDialog.teamsHint") }}</p>

      <ul class="rows">
        <li v-for="team in data?.teams ?? []" :key="team.id" class="team">
          <Card size="sm" as-child>
            <div class="row">
              <template v-if="renaming?.id === team.id">
                <Input v-model="renaming.name" class="fill" size="sm" @keydown.enter.prevent="
                  act(async () => {
                    await renameTeam(workspaceId, team.id, renaming!.name.trim());
                    renaming = null;
                  })
                " />
                <Button variant="outline" size="sm" @click="renaming = null">
                  {{ t("common.cancel") }}
                </Button>
                <Button
                  size="sm"
                  :disabled="!renaming.name.trim() || busy"
                  @click="
                    act(async () => {
                      await renameTeam(workspaceId, team.id, renaming!.name.trim());
                      renaming = null;
                    })
                  "
                >
                  {{ t("common.save") }}
                </Button>
              </template>
              <template v-else>
                <span class="grow">
                  <Button
                    variant="text"
                    size="sm"
                    :leading-icon="openTeam === team.id ? ChevronDown : ChevronRight"
                    :aria-expanded="openTeam === team.id"
                    @click="toggleTeam(team.id)"
                  >
                    {{ team.name }}
                  </Button>
                </span>
                <Button
                  variant="text"
                  size="sm"
                  @click="renaming = { id: team.id, name: team.name }"
                >
                  {{ t("MembersDialog.rename") }}
                </Button>
                <Button
                  variant="text"
                  color="danger"
                  size="sm"
                  :disabled="busy"
                  @click="act(() => removeTeam(workspaceId, team.id))"
                >
                  {{ t("common.delete") }}
                </Button>
              </template>
            </div>
          </Card>

          <div v-if="openTeam === team.id" class="members">
            <EmptyState
              v-if="!openTeamMembers.length"
              size="sm"
              :title="t('MembersDialog.teamEmpty')"
            />
            <ul class="rows">
              <Card v-for="member in openTeamMembers" :key="member.userId" size="sm" as-child>
                <li class="row">
                  <span class="grow">
                    <span class="name">{{ label(member) }}</span>
                    <span v-if="byUserId.get(member.userId)?.user?.email" class="muted">
                      {{ byUserId.get(member.userId)!.user!.email }}
                    </span>
                  </span>
                  <Button
                    variant="text"
                    color="danger"
                    size="sm"
                    :disabled="busy"
                    @click="
                      removeAndOffer(label(member), member.userId, () =>
                        removeTeamMember(workspaceId, team.id, member.userId),
                      )
                    "
                  >
                    {{ t("common.remove") }}
                  </Button>
                </li>
              </Card>
            </ul>

            <Card v-if="teamCandidates.length" size="sm" as-child>
              <div class="row">
                <NativeSelect
                  class="fill"
                  size="sm"
                  :items="teamCandidates.map((row) => ({ value: row.userId, label: label(row) }))"
                  :placeholder="t('MembersDialog.addMemberPlaceholder')"
                  :aria-label="t('MembersDialog.addMember')"
                  :disabled="busy"
                  @update:model-value="act(() => addTeamMember(workspaceId, team.id, $event))"
                />
              </div>
            </Card>
          </div>
        </li>
      </ul>

      <Card size="sm" as-child>
        <div class="row">
          <Input
            v-model="newTeam"
            class="fill"
            size="sm"
            :placeholder="t('MembersDialog.teamName')"
            @keydown.enter.prevent="
              act(async () => {
                await createTeam(workspaceId, newTeam.trim());
                newTeam = '';
              })
            "
          />
          <Button
            size="sm"
            :disabled="!newTeam.trim() || busy"
            @click="
              act(async () => {
                await createTeam(workspaceId, newTeam.trim());
                newTeam = '';
              })
            "
          >
            {{ t("MembersDialog.create") }}
          </Button>
        </div>
      </Card>
    </template>

    <Alert v-if="removed && stale.length" status="warn" size="sm" class="rotate">
      <p>
        {{
          t("MembersDialog.staleWarning", {
            name: removed,
            projects: stale
              .map((project) => t("MembersDialog.quoted", { name: project.name }))
              .join(", "),
          })
        }}
      </p>
      <div class="row">
        <Button size="sm" :disabled="rotating" @click="rotateAll">
          {{ rotating ? t("MembersDialog.rotating") : t("MembersDialog.rotateNow") }}
        </Button>
        <Button variant="text" size="sm" :disabled="rotating" @click="removed = null">
          {{ t("MembersDialog.later") }}
        </Button>
      </div>
    </Alert>
    <Alert v-if="rotated.length" :status="rotated.every((r) => r.ok) ? 'success' : 'warn'" size="sm">
      <p v-for="entry in rotated" :key="entry.name">{{ entry.name }}: {{ entry.outcome }}</p>
    </Alert>

    <Alert v-if="error" class="error" status="danger" size="sm">{{ error }}</Alert>

    <template #actions>
      <Button variant="text" :disabled="busy" @click="refresh">{{ t("MembersDialog.refresh") }}</Button>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('close')">{{ t("common.close") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
/* Font and color come from `label-mono`, WireLayer's label style. */
h4 {
  margin: 1.25rem 0 0.5rem;
  font-weight: 400;
}

.hint {
  margin: 0.4rem 0 0;
  font-size: 0.8rem;
  line-height: 1.5;
  color: var(--muted);
}

.error {
  margin-top: 0.75rem;
}

.rows {
  list-style: none;
  margin: 0.5rem 0 0;
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
  box-sizing: border-box;
  font-size: 0.9rem;
}

.rows + .row,
.team + .row,
.row + .row {
  margin-top: 0.35rem;
}

.team {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.members {
  padding-left: 1rem;
}

.grow {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  flex-wrap: wrap;
}

/* Inputs in a row: the field takes the rest, the selects only what they need. */
.fill {
  flex: 1;
  min-width: 0;
}

.select {
  flex: 0 0 auto;
  width: auto;
}

.name {
  font-weight: 500;
}

.muted {
  color: var(--muted);
  font-size: 0.85em;
}

.spacer {
  flex: 1;
}
</style>
