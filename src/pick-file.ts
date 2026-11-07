import { open, save } from "@tauri-apps/plugin-dialog";

/**
 * The native "Open file" dialog for the fields that hold a path.
 *
 * `null` when it was cancelled — the field then stays as it was. The text
 * field next to it stays where it is: a path copied from somewhere is pasted
 * faster than clicked together.
 */
export async function pickFile(
  title: string,
  current: string,
  filters?: { name: string; extensions: string[] }[],
): Promise<string | null> {
  const picked = await open({
    title,
    multiple: false,
    directory: false,
    defaultPath: current.trim() || undefined,
    filters,
  });
  return typeof picked === "string" ? picked : null;
}

/** The native "Save as" dialog. `null` when it was cancelled. */
export async function pickSaveFile(
  title: string,
  defaultPath: string,
  filters?: { name: string; extensions: string[] }[],
): Promise<string | null> {
  return (await save({ title, defaultPath, filters })) ?? null;
}
