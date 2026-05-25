let toasts = $state([]);

let counter = 0;

export function showToast(message, type = 'error', duration = 3000) {
  const id = ++counter;
  toasts = [...toasts, { id, message, type }];

  setTimeout(() => {
    toasts = toasts.filter(t => t.id !== id);
  }, duration);
}

export function getToasts() {
  return toasts;
}