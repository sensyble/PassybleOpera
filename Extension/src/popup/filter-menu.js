import { openMenu } from '../ui/popover.js';
import { t } from '../shared/i18n.js';

export function mountFilterMenu(button, clear, { vaults, types, onChange }) {
  const name = button.querySelector('.filter-name');

  const chosen = () => [vaults.label, types.label].filter(Boolean);

  function render() {
    const parts = chosen();
    const text = parts.length ? parts.join(' · ') : t('popupFilter');
    name.textContent = text;
    button.classList.toggle('active', parts.length > 0);
    button.title = parts.length ? t('popupFilterShowing', text) : t('popupFilter');
    button.setAttribute('aria-label', button.title);
    clear.hidden = !parts.length;
  }

  function reset() {
    const changed = [vaults.reset(), types.reset()].some(Boolean);
    render();
    if (changed) onChange();
  }

  button.addEventListener('click', () => {
    const vaultItems = vaults.items();
    openMenu(button, [
      ...(vaultItems.length ? [{ heading: t('popupFilterVaults') }, ...vaultItems] : []),
      { heading: t('popupFilterShow'), label: t('popupTypeFilter') },
      ...types.items(),
      ...(chosen().length ? ['sep', { id: 'filter-reset', icon: 'close', label: t('popupFilterClear'), onSelect: reset }] : []),
    ], { label: t('popupFilter'), compact: true });
  });
  clear.addEventListener('click', () => { reset(); button.focus(); });
  clear.title = t('popupFilterClear');
  clear.setAttribute('aria-label', t('popupFilterClear'));
  render();

  return { render };
}
