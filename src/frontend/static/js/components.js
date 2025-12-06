const Components = {
    createModal: (id, title, content) => {
        const modal = document.createElement('div');
        modal.id = id;
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/50 opacity-0 pointer-events-none transition-opacity duration-300';
        modal.innerHTML = `
            <div class="bg-surface border border-slate-700 rounded-lg shadow-xl w-full max-w-lg transform scale-95 transition-transform duration-300">
                <div class="flex justify-between items-center p-4 border-b border-slate-700">
                    <h3 class="text-lg font-bold">${title}</h3>
                    <button class="text-muted hover:text-white" onclick="Components.closeModal('${id}')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="p-6">
                    ${content}
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        return modal;
    },

    openModal: (id) => {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.remove('opacity-0', 'pointer-events-none');
            modal.querySelector('div').classList.remove('scale-95');
            modal.querySelector('div').classList.add('scale-100');
        }
    },

    closeModal: (id) => {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.add('opacity-0', 'pointer-events-none');
            modal.querySelector('div').classList.remove('scale-100');
            modal.querySelector('div').classList.add('scale-95');
            setTimeout(() => modal.remove(), 300);
        }
    },

    createSpinner: (size = 'md') => {
        const sizes = { sm: 'text-sm', md: 'text-xl', lg: 'text-3xl' };
        return `<i class="fas fa-spinner fa-spin ${sizes[size]} text-primary"></i>`;
    }
};

window.Components = Components;
