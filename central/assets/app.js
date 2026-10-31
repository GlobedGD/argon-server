document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
        if (!confirm(form.dataset.confirm)) {
            event.preventDefault();
        }
    });
});

document.addEventListener('click', (event) => {
    const close = event.target.closest('.toast-close');
    if (close) {
        close.closest('.toast').remove();
    }
});