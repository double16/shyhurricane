"use server";

export async function save(form) {
  return String(form.get("label") ?? "");
}

export async function preview(label) {
  return String(label);
}
