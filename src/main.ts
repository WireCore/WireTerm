import { createApp } from "vue";
import "./styles.css";
import { registerLocale } from "@wirecore/wirelayer-vue";
import { de } from "@wirecore/wirelayer-vue/locales/de";
import App from "./App.vue";
import { i18n, initLocale } from "./i18n";
import { watchForUpdates } from "./updates";

// WireLayer's built-in texts in German; English is its default. The
// LocaleProvider in App.vue picks the one in effect.
registerLocale("de", de);

// The Rust side learns the language before the first message it builds.
initLocale()
  .catch(() => undefined)
  .finally(() => {
    createApp(App).use(i18n).mount("#app");
    watchForUpdates();
  });
