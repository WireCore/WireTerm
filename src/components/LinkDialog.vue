<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Alert, Button, Field, Input, NativeSelect } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";

/**
 * "Create link" — handing a file over without handing it over.
 *
 * The one gesture that exists over S3 and nowhere else. A presigned URL
 * carries its own signature, so whoever gets it can fetch that one object
 * without an account, without a key and without this app — and only until it
 * expires.
 *
 * That is also why the validity is asked before the link is made rather than
 * being a setting somewhere: it is the whole of what is being decided here.
 * The shortest offer is the default, because a link that outlives the reason
 * it was made for is the failure mode worth designing against.
 */
const props = defineProps<{
  name: string;
  /** Empty until one has been made; what is on screen afterwards. */
  url: string;
  busy: boolean;
  error: string;
}>();

const emit = defineEmits<{ create: [seconds: number]; close: [] }>();
const { t } = useI18n();

const HOUR = 60 * 60;

/** Seven days is SigV4's own ceiling, not a choice made here. */
const SPANS = computed<{ value: number; label: string }[]>(() => [
  { value: HOUR, label: t("LinkDialog.spans.hour") },
  { value: 8 * HOUR, label: t("LinkDialog.spans.eightHours") },
  { value: 24 * HOUR, label: t("LinkDialog.spans.day") },
  { value: 7 * 24 * HOUR, label: t("LinkDialog.spans.week") },
]);

const seconds = ref(SPANS.value[0].value);
const field = ref<InstanceType<typeof Input>>();
const copied = ref(false);

/**
 * Copies the link, and falls back to the old command where the clipboard API
 * is not available — which in a webview is not a rare case worth ignoring.
 * Either way the field is selected afterwards, so a failure still leaves the
 * link ready for Ctrl+C rather than leaving the user with nothing.
 */
async function copy() {
  field.value?.select();
  try {
    await navigator.clipboard.writeText(field.value?.element?.value ?? "");
    copied.value = true;
    setTimeout(() => (copied.value = false), 2000);
  } catch {
    copied.value = document.execCommand?.("copy") ?? false;
  }
}

/** Selected as soon as it arrives: the next thing anyone does is copy it. */
watch(
  () => props.url,
  async (url) => {
    if (!url) return;
    await nextTick();
    field.value?.select();
  },
);
</script>

<template>
  <EditDialog :title="t('LinkDialog.title')" @save="emit('create', seconds)" @cancel="emit('close')">
    <i18n-t keypath="LinkDialog.lead" tag="p" class="lead">
      <template #name>
        <code>{{ name }}</code>
      </template>
    </i18n-t>

    <Field :label="t('LinkDialog.validFor')">
      <NativeSelect v-model="seconds" :items="SPANS" :disabled="busy" />
    </Field>

    <div v-if="url" class="result">
      <Input ref="field" class="url" :model-value="url" readonly spellcheck="false" mono />
      <Button variant="outline" @click="copy">{{ copied ? t("LinkDialog.copied") : t("LinkDialog.copy") }}</Button>
    </div>

    <Alert v-if="error" status="danger" size="sm" class="error">{{ error }}</Alert>

    <template #actions>
      <span class="spacer"></span>
      <Button variant="outline" @click="emit('close')">{{ t("common.close") }}</Button>
      <Button :disabled="busy" @click="emit('create', seconds)">
        {{
          busy ? t("LinkDialog.creating") : url ? t("LinkDialog.recreate") : t("LinkDialog.create")
        }}
      </Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.lead {
  margin: 0 0 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
  color: var(--muted);
}

code {
  font-family: Consolas, Menlo, monospace;
  font-size: 0.85rem;
  color: var(--fg);
  word-break: break-all;
}

.result {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.75rem;
}

/* A presigned URL is several hundred characters of signature; it is there to
   be copied, not to be read. */
.url {
  flex: 1;
  min-width: 0;
}

.url :deep(input) {
  font-size: 0.75rem;
}

.error {
  margin-top: 0.75rem;
  word-break: break-word;
}

.spacer {
  flex: 1;
}
</style>
