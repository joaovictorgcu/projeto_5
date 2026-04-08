/* ═══════════════════════════════════════════════════════════════
   Keyflow — JavaScript do Frontend v2.0
   Dark Mode, Animacoes, Gerador de Senhas, Reveal/Copy
   ═══════════════════════════════════════════════════════════════ */

/* ─── CSRF Token ────────────────────────────────────────────── */
function getCSRFToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

/* ─── Dark Mode ─────────────────────────────────────────────── */
function toggleTheme() {
    var html = document.documentElement;
    var current = html.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('keyflow-theme', next);
    updateThemeIcon(next);
}

function updateThemeIcon(theme) {
    var icon = document.getElementById('theme-icon-svg');
    if (icon) {
        var use = icon.querySelector('use');
        if (use) {
            use.setAttribute('href', theme === 'dark' ? '#icon-sun' : '#icon-moon');
        }
    }
}

// Aplicar tema salvo
(function() {
    var saved = localStorage.getItem('keyflow-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
        // Icon sera atualizado no DOMContentLoaded
    }
})();

/* ─── Revelar Senha ─────────────────────────────────────────── */
function revealPassword(credId) {
    var el = document.getElementById('pw-' + credId);

    if (el.classList.contains('password-revealed')) {
        el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
        el.classList.remove('password-revealed');
        el.classList.add('password-mask');
        return;
    }

    // Animacao de loading
    el.textContent = '...';
    el.style.animation = 'pulse 0.5s ease infinite';

    fetch('/vault/' + credId + '/reveal', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        }
    })
    .then(function(response) { return response.json(); })
    .then(function(data) {
        el.style.animation = '';
        if (data.error) {
            showToast(data.error, 'error');
            el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
            return;
        }
        el.textContent = data.password;
        el.classList.remove('password-mask');
        el.classList.add('password-revealed');

        setTimeout(function() {
            if (el.classList.contains('password-revealed')) {
                el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
                el.classList.remove('password-revealed');
                el.classList.add('password-mask');
            }
        }, 30000);
    })
    .catch(function() {
        el.style.animation = '';
        el.textContent = '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';
        showToast('Erro ao revelar senha.', 'error');
    });
}

/* ─── Copiar Senha ──────────────────────────────────────────── */
function copyPassword(credId) {
    var el = document.getElementById('pw-' + credId);

    if (el.classList.contains('password-revealed')) {
        copyText(el.textContent);
        return;
    }

    fetch('/vault/' + credId + '/reveal', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        }
    })
    .then(function(response) { return response.json(); })
    .then(function(data) {
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }
        copyText(data.password);
    })
    .catch(function() {
        showToast('Erro ao copiar senha.', 'error');
    });
}

/* ─── Copiar Texto ──────────────────────────────────────────── */
function copyText(text) {
    navigator.clipboard.writeText(text).then(function() {
        showToast('Copiado!');
    }).catch(function() {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast('Copiado!');
    });
}

/* ─── Gerador de Senhas ─────────────────────────────────────── */
function generatePassword() {
    var length = parseInt(document.getElementById('pw-length').value) || 16;
    var useUpper = document.getElementById('pw-upper').checked;
    var useLower = document.getElementById('pw-lower').checked;
    var useNumbers = document.getElementById('pw-numbers').checked;
    var useSymbols = document.getElementById('pw-symbols').checked;

    var chars = '';
    var required = [];

    if (useUpper) { chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; required.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); }
    if (useLower) { chars += 'abcdefghijklmnopqrstuvwxyz'; required.push('abcdefghijklmnopqrstuvwxyz'); }
    if (useNumbers) { chars += '0123456789'; required.push('0123456789'); }
    if (useSymbols) { chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'; required.push('!@#$%^&*()_+-=[]{}|;:,.<>?'); }

    if (!chars) {
        showToast('Selecione pelo menos um tipo de caractere.', 'error');
        return;
    }

    var password = '';
    var array = new Uint32Array(length);
    crypto.getRandomValues(array);

    // Garantir que ao menos 1 de cada tipo selecionado esta presente
    for (var r = 0; r < required.length && r < length; r++) {
        var reqChars = required[r];
        password += reqChars[array[r] % reqChars.length];
    }

    // Preencher o restante
    for (var i = required.length; i < length; i++) {
        password += chars[array[i] % chars.length];
    }

    // Embaralhar
    password = password.split('').sort(function() { return 0.5 - Math.random(); }).join('');

    var field = document.getElementById('password');
    field.value = password;
    field.type = 'text';
    var btn = document.querySelector('.btn-toggle-pw');
    if (btn) btn.textContent = 'Ocultar';

    updatePasswordStrength(password);
    showToast('Senha gerada!');
}

/* ─── Forca da Senha ────────────────────────────────────────── */
function updatePasswordStrength(password) {
    var bar = document.getElementById('pw-strength-bar');
    var label = document.getElementById('pw-strength-label');
    if (!bar || !label) return;

    if (!password) {
        bar.style.width = '0';
        label.textContent = '';
        return;
    }

    var score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;

    var levels = [
        { max: 1, color: '#ef4444', text: 'Muito fraca' },
        { max: 2, color: '#f97316', text: 'Fraca' },
        { max: 3, color: '#eab308', text: 'Razoavel' },
        { max: 4, color: '#22c55e', text: 'Boa' },
        { max: 6, color: '#16a34a', text: 'Forte' }
    ];

    var level = levels[0];
    for (var j = 0; j < levels.length; j++) {
        if (score <= levels[j].max) { level = levels[j]; break; }
        level = levels[j];
    }

    var pct = Math.min((score / 6) * 100, 100);
    bar.style.width = pct + '%';
    bar.style.background = level.color;
    label.textContent = level.text;
    label.style.color = level.color;
}

/* ─── Toggle Password Field ────────────────────────────────── */
function togglePasswordField(fieldId) {
    var field = document.getElementById(fieldId);
    var btn = field.parentElement.querySelector('.btn-toggle-pw');

    if (field.type === 'password') {
        field.type = 'text';
        btn.textContent = 'Ocultar';
    } else {
        field.type = 'password';
        btn.textContent = 'Mostrar';
    }
}

/* ─── Toast Notifications ───────────────────────────────────── */
function showToast(message, type) {
    var bg = type === 'error' ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 'linear-gradient(135deg, #1f2937, #111827)';
    var toast = document.createElement('div');
    toast.textContent = message;
    toast.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:' + bg + ';color:white;padding:0.75rem 1.5rem;border-radius:12px;font-size:0.85rem;font-weight:600;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,0.2);transform:translateY(20px);opacity:0;transition:all 0.3s cubic-bezier(0.4,0,0.2,1)';
    document.body.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(function() {
        toast.style.transform = 'translateY(0)';
        toast.style.opacity = '1';
    });

    setTimeout(function() {
        toast.style.transform = 'translateY(20px)';
        toast.style.opacity = '0';
        setTimeout(function() { toast.remove(); }, 300);
    }, 2500);
}

/* ─── Animated Counters (Landing & Dashboard) ───────────────── */
function animateCounters() {
    var counters = document.querySelectorAll('[data-count]');
    counters.forEach(function(el) {
        var target = parseInt(el.getAttribute('data-count'));
        if (isNaN(target) || target === 0) return;

        var current = 0;
        var duration = 1000;
        var step = target / (duration / 16);

        function update() {
            current += step;
            if (current >= target) {
                el.textContent = target;
                return;
            }
            el.textContent = Math.floor(current);
            requestAnimationFrame(update);
        }
        update();
    });
}

/* ─── Intersection Observer for Animations ──────────────────── */
function setupScrollAnimations() {
    var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    document.querySelectorAll('.feature-card, .step-card, .pricing-card, .stat-card').forEach(function(el) {
        el.style.opacity = '0';
        observer.observe(el);
    });
}

/* ─── DOMContentLoaded ──────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    // Tema
    var saved = localStorage.getItem('keyflow-theme');
    if (saved) updateThemeIcon(saved);

    // Auto-fechar flash messages
    document.querySelectorAll('.flash').forEach(function(flash) {
        setTimeout(function() {
            flash.style.opacity = '0';
            flash.style.transform = 'translateY(-10px)';
            flash.style.transition = 'all 0.3s ease';
            setTimeout(function() { flash.remove(); }, 300);
        }, 5000);
    });

    // Monitorar campo de senha para indicador de forca
    var pwField = document.getElementById('password');
    if (pwField) {
        pwField.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }

    // Contadores animados
    animateCounters();

    // Scroll animations na landing
    if (document.querySelector('.landing')) {
        setupScrollAnimations();
    }

    // Adicionar delay staggered nas cards
    document.querySelectorAll('.credential-card').forEach(function(card, i) {
        card.style.animationDelay = (i * 0.05) + 's';
    });
});

/* ─── Keyboard Shortcuts ────────────────────────────────────── */
document.addEventListener('keydown', function(e) {
    // Ignore when typing in input/textarea
    var tag = document.activeElement.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

    // Ctrl+K or / = focus search
    if ((e.ctrlKey && e.key === 'k') || e.key === '/') {
        e.preventDefault();
        var searchInput = document.querySelector('.search-bar input');
        if (searchInput) searchInput.focus();
    }

    // N = new credential (when on vault page)
    if (e.key === 'n' && !e.ctrlKey && !e.metaKey) {
        var newBtn = document.querySelector('a[href*="vault/new"]');
        if (newBtn) { e.preventDefault(); newBtn.click(); }
    }

    // ? = toggle shortcuts help
    if (e.key === '?' && !e.ctrlKey) {
        e.preventDefault();
        toggleShortcutsHelp();
    }
});

function toggleShortcutsHelp() {
    var existing = document.getElementById('shortcuts-panel');
    if (existing) { existing.remove(); return; }

    var panel = document.createElement('div');
    panel.id = 'shortcuts-panel';
    panel.innerHTML = '<div style="position:fixed;bottom:1rem;right:1rem;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;box-shadow:0 8px 24px rgba(0,0,0,0.15);z-index:9999;min-width:220px;">' +
        '<h4 style="font-size:0.85rem;font-weight:700;margin-bottom:0.75rem;color:var(--text-primary);">Atalhos de teclado</h4>' +
        '<div style="font-size:0.8rem;color:var(--text-secondary);line-height:2;">' +
        '<div><kbd style="background:var(--gray-100);padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;font-weight:600;">Ctrl+K</kbd> Buscar</div>' +
        '<div><kbd style="background:var(--gray-100);padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;font-weight:600;">N</kbd> Nova credencial</div>' +
        '<div><kbd style="background:var(--gray-100);padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;font-weight:600;">?</kbd> Este painel</div>' +
        '</div>' +
        '<button onclick="this.parentElement.parentElement.remove()" style="position:absolute;top:0.5rem;right:0.75rem;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.1rem;">×</button>' +
        '</div>';
    document.body.appendChild(panel);
}
