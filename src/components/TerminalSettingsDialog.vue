<script setup lang="ts">
import { useI18n } from "vue-i18n";
import { Button, Divider, Field, NativeSelect, NumberInput, Switch } from "@wirecore/wirelayer-vue";
import EditDialog from "./EditDialog.vue";
import {
  CONTRAST_LEVELS,
  CURSOR_STYLES,
  FONT_FAMILIES,
  TERMINAL_THEMES,
  resetTerminalSettings,
  terminalSettings,
} from "../terminal-settings";

/**
 * Edits the live settings object rather than a copy: the point of a theme
 * picker is watching the terminal behind the dialog change. There is nothing
 * to confirm, so the footer offers "Reset" and "Done" instead.
 */
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();

/** The six that tell two palettes apart at a glance. */
const SWATCH_KEYS = ["red", "green", "yellow", "blue", "magenta", "cyan"] as const;
</script>

<template>
  <!-- Changes take effect as they are made, so "Done" and Cancel are the
       same thing: both just close it. Bound so Enter closes it too. -->
  <EditDialog
    wide
    :title="t('TerminalSettingsDialog.title')"
    @save="emit('close')"
    @cancel="emit('close')"
  >
    <section>
      <h4>{{ t("TerminalSettingsDialog.theme") }}</h4>
      <p class="hint">{{ t("TerminalSettingsDialog.themeHint") }}</p>

      <div class="themes">
        <button
          v-for="preset in TERMINAL_THEMES"
          :key="preset.id"
          class="swatch"
          :class="{ active: preset.id === terminalSettings.theme }"
          type="button"
          :style="{ background: preset.theme.background, color: preset.theme.foreground }"
          :title="preset.label"
          @click="terminalSettings.theme = preset.id"
        >
          <span class="swatch-name">{{ preset.label }}</span>
          <span class="dots">
            <span
              v-for="key in SWATCH_KEYS"
              :key="key"
              class="dot"
              :style="{ background: preset.theme[key] }"
            ></span>
          </span>
        </button>
      </div>
    </section>

    <Divider class="sep" />

    <section>
      <h4>{{ t("TerminalSettingsDialog.font") }}</h4>

      <div class="row">
        <Field class="field grow" :label="t('TerminalSettingsDialog.fontFamily')">
          <NativeSelect v-model="terminalSettings.fontFamily" :items="FONT_FAMILIES" />
        </Field>
        <!-- An emptied field gets the last number back rather than writing null. -->
        <Field class="field narrow" :label="t('TerminalSettingsDialog.fontSize')">
          <NumberInput
            v-model="terminalSettings.fontSize"
            empty-fallback="previous"
            :min="8"
            :max="32"
            :stepper="false"
          />
        </Field>
        <Field class="field narrow" :label="t('TerminalSettingsDialog.lineHeight')">
          <NumberInput
            v-model="terminalSettings.lineHeight"
            empty-fallback="previous"
            :min="1"
            :max="2"
            :step="0.05"
            :stepper="false"
          />
        </Field>
      </div>

      <p class="hint">{{ t("TerminalSettingsDialog.fontHint") }}</p>
    </section>

    <Divider class="sep" />

    <section>
      <h4>{{ t("TerminalSettingsDialog.cursor") }}</h4>
      <div class="row">
        <Field class="field grow" :label="t('TerminalSettingsDialog.cursorStyle')">
          <NativeSelect v-model="terminalSettings.cursorStyle" :items="CURSOR_STYLES" />
        </Field>
        <Switch v-model:checked="terminalSettings.cursorBlink" class="check">
          {{ t("TerminalSettingsDialog.cursorBlink") }}
        </Switch>
      </div>
    </section>

    <Divider class="sep" />

    <section>
      <h4>{{ t("TerminalSettingsDialog.readability") }}</h4>

      <Field
        class="field"
        :label="t('TerminalSettingsDialog.minimumContrast')"
        :helper-text="t('TerminalSettingsDialog.minimumContrastHint')"
      >
        <NativeSelect v-model="terminalSettings.minimumContrastRatio" :items="CONTRAST_LEVELS" />
      </Field>

      <Field
        class="field"
        :label="t('TerminalSettingsDialog.scrollback')"
        :helper-text="t('TerminalSettingsDialog.scrollbackHint')"
      >
        <NumberInput
          v-model="terminalSettings.scrollback"
          empty-fallback="previous"
          :min="1000"
          :max="200000"
          :step="1000"
        />
      </Field>

      <Switch
        v-model:checked="terminalSettings.drawBoldTextInBrightColors"
        class="check"
        :description="t('TerminalSettingsDialog.boldBrightHint')"
      >
        {{ t("TerminalSettingsDialog.boldBright") }}
      </Switch>
    </section>

    <template #actions>
      <Button variant="text" @click="resetTerminalSettings">{{ t("common.reset") }}</Button>
      <span class="grow-spacer"></span>
      <Button @click="emit('close')">{{ t("common.done") }}</Button>
    </template>
  </EditDialog>
</template>

<style scoped>
.sep {
  margin: 1rem 0;
}

h4 {
  margin: 0 0 0.5rem;
  font-size: 0.9rem;
}

.themes {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(9rem, 1fr));
  gap: 0.5rem;
}

/* The preview is the palette itself: the card is painted in the theme it
   offers, which says more than any name. */
.swatch {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.4rem;
  padding: 0.6rem;
  border-radius: 12px;
  border: 1px solid var(--color-line-2);
  text-align: left;
  overflow: hidden;
  cursor: pointer;
  transition: border-color 150ms, box-shadow 150ms;
}

/* Like the hover and focus states of the WireLayer components. */
.swatch:hover:not(:disabled) {
  border-color: var(--color-line-strong);
}

.swatch:focus-visible {
  outline: 2px solid var(--color-fg);
  outline-offset: 2px;
}

/* A ring instead of a thicker border: that way the tile does not jump when selected. */
.swatch.active {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 1px var(--color-primary);
}

@media (prefers-reduced-motion: reduce) {
  .swatch {
    transition: none;
  }
}

.swatch-name {
  font-size: 0.8rem;
  font-weight: 600;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dots {
  display: flex;
  gap: 0.2rem;
}

.dot {
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 50%;
}

.field {
  margin-bottom: 0.5rem;
}

.row {
  display: flex;
  align-items: flex-end;
  gap: 0.75rem;
}

.grow {
  flex: 1;
  min-width: 0;
}

.narrow {
  width: 6.5rem;
  flex: 0 0 6.5rem;
}

.check {
  margin-bottom: 0.5rem;
  padding-bottom: 0.45em;
}

.hint {
  margin: 0 0 0.75rem;
  font-size: 0.8rem;
  color: var(--color-muted);
  line-height: 1.4;
}

/* The slot content is compiled in this component's scope, so the dialog's own
   spacer class does not reach it. */
.grow-spacer {
  flex: 1;
}
</style>
