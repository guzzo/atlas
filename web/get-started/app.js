const stepButtons = document.querySelectorAll('[data-step]');
for (const button of stepButtons) {
  button.addEventListener('click', () => {
    for (const step of stepButtons) {
      const active = step === button;
      step.classList.toggle('is-active', active);
      step.setAttribute('aria-pressed', String(active));
      document.getElementById(step.getAttribute('aria-controls')).hidden = !active;
    }
  });
}

for (const button of document.querySelectorAll('[data-copy]')) {
  let reset;
  button.addEventListener('click', async () => {
    const source = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      button.textContent = 'Copied ✓';
      status.textContent = `${button.getAttribute('aria-label').replace(/^Copy /, '')} copied.`;
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Text selected';
      status.textContent = 'Clipboard unavailable. Text selected; use your device’s copy command.';
    }
    reset = setTimeout(() => (button.textContent = 'Copy ⧉'), 2200);
  });
}
