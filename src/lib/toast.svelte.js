/** @type {Array<{id: number, message: string, type: string}>} */
let toasts = $state([]);

let counter = 0;

export function getToasts() {
  return toasts;
}

export function showToast(message, type = 'error', duration = 3000) {
  const id = ++counter;
  toasts.push({ id, message, type });

  setTimeout(() => {
    const idx = toasts.findIndex(t => t.id === id);
    if (idx !== -1) toasts.splice(idx, 1);
  }, duration);
}
