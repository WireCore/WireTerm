<script setup lang="ts">
/**
 * This device's default proxy.
 *
 * Applies to every connection that says nothing else — in every workspace,
 * including those from the backend. It does not travel along itself: whether a
 * proxy is needed depends on the network this machine is in. The password is
 * stored in `proxy.json`, encrypted with the device key.
 */
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import {
  Alert,
  Checkbox,
  Field,
  Input,
  NativeSelect,
  NumberInput,
  PasswordInput,
} from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import { defaultProxy, PROXY_PORTS, setDefaultProxy } from "../proxy";
import { PROXY_KIND_LABELS, type DefaultProxy, type ProxyKind } from "../types";

const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

const KINDS = (Object.keys(PROXY_KIND_LABELS) as ProxyKind[]).map((kind) => ({
  value: kind,
  label: PROXY_KIND_LABELS[kind],
}));

const enabled = ref(false);
const draft = ref<DefaultProxy>({ kind: "socks5", host: "", port: 1080, user: "", password: "" });
const loaded = ref(false);
const busy = ref(false);
const error = ref("");

onMounted(async () => {
  try {
    const current = await defaultProxy();
    if (current) {
      draft.value = current;
      enabled.value = true;
    }
  } catch (e) {
    error.value = String(e);
  } finally {
    loaded.value = true;
  }
});

function setKind(kind: ProxyKind) {
  // Only carry the port along while it was the usual one of the other kind.
  if (draft.value.port === PROXY_PORTS[draft.value.kind]) draft.value.port = PROXY_PORTS[kind];
  draft.value.kind = kind;
}

const valid = computed(
  () => loaded.value && !busy.value && (!enabled.value || draft.value.host.trim() !== ""),
);

async function save() {
  if (!valid.value) return;
  busy.value = true;
  error.value = "";
  try {
    await setDefaultProxy(enabled.value ? { ...draft.value, host: draft.value.host.trim() } : null);
    emit("close");
  } catch (e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <EditDialog :title="t('ProxyDialog.title')" :can-save="valid" @save="save" @cancel="emit('close')">
    <p class="hint">{{ t("ProxyDialog.hint") }}</p>

    <Checkbox v-model:checked="enabled" :disabled="!loaded">{{ t("ProxyDialog.enabled") }}</Checkbox>

    <template v-if="enabled">
      <div class="row spaced">
        <Field :label="t('ProxyDialog.kind')" class="kind">
          <NativeSelect
            :model-value="draft.kind"
            :items="KINDS"
            @update:model-value="setKind($event as ProxyKind)"
          />
        </Field>
        <Field label="Host" class="grow">
          <Input
            v-model="draft.host"
            :placeholder="t('ProxyDialog.hostPlaceholder')"
            autocapitalize="off"
            spellcheck="false"
            data-autofocus
          />
        </Field>
        <Field label="Port" class="port">
          <NumberInput
            v-model="draft.port"
            :min="1"
            :max="65535"
            :allow-decimal="false"
            :allow-negative="false"
            :format-options="{ useGrouping: false }"
            :stepper="false"
          />
        </Field>
      </div>
      <div class="row">
        <Field :label="t('ProxyDialog.user')" class="grow" :helper-text="t('ProxyDialog.userHint')">
          <Input v-model="draft.user" autocapitalize="off" spellcheck="false" autocomplete="off" />
        </Field>
        <Field :label="t('common.password')" class="grow">
          <PasswordInput v-model="draft.password" :disabled="!draft.user" autocomplete="off" />
        </Field>
      </div>
      <p class="hint">{{ t("ProxyDialog.dnsHint") }}</p>
    </template>

    <Alert v-if="error" status="danger" size="sm" class="spaced">{{ error }}</Alert>
  </EditDialog>
</template>

<style scoped>
.row {
  display: flex;
  gap: 0.75rem;
}

.grow {
  flex: 1;
  min-width: 0;
}

.kind {
  width: 11rem;
}

.port {
  width: 6.5rem;
}

.spaced {
  margin-top: 1rem;
}

.hint {
  color: var(--muted);
  font-size: 0.85rem;
  margin: 0 0 0.75rem;
}
</style>
