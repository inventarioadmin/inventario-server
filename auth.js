
function handleAuthentication() {
    // Pega o token atual
    const token = localStorage.getItem('token');
    
    // Se não houver token, redireciona para login
    if (!token) {
        if (window.location.pathname !== '/') {
            window.location.href = '/';
        }
        return false;
    }

    // Decodifica o token para verificar o tipo de usuário
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(window.atob(base64));

        // Verifica o tipo de usuário e redireciona apropriadamente
        if (payload.role === 'superadmin') {
            if (window.location.pathname !== '/superadmin') {
                window.location.href = '/superadmin';
            }
        } else if (payload.role === 'admin') {
            if (window.location.pathname !== '/admin') {
                window.location.href = '/admin';
            }
        }

        return true;
    } catch (error) {
        console.error('Erro ao decodificar token:', error);
        localStorage.clear();
        if (window.location.pathname !== '/') {
            window.location.href = '/';
        }
        return false;
    }
}

// Modifique o script de login para incluir o role no localStorage
async function handleLogin(event) {
    event.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('role', data.role); // Armazena o role

            // Redireciona baseado no role
            if (data.role === 'superadmin') {
                window.location.href = '/superadmin';
            } else if (data.role === 'admin') {
                window.location.href = '/admin';
            }
        } else {
            alert(data.message || 'Erro ao fazer login');
        }
    } catch (error) {
        console.error('Erro:', error);
        alert('Erro ao fazer login');
    }
}

// Adicione esta função para verificar permissões de acesso à página
function checkPageAccess() {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');

    if (!token || !role) {
        window.location.href = '/';
        return false;
    }

    // Verifica se o usuário tem permissão para acessar a página atual
    const currentPath = window.location.pathname;
    
    if (currentPath === '/admin' && role !== 'admin') {
        window.location.href = '/';
        return false;
    }
    
    if (currentPath === '/superadmin' && role !== 'superadmin') {
        window.location.href = '/';
        return false;
    }

    return true;
}

// Modifique o checkAuth no company-panel.html
function checkAuth() {
    if (!checkPageAccess()) return false;
    
    const token = localStorage.getItem('token');
    if (!token) {
        localStorage.clear();
        window.location.href = '/';
        return false;
    }
    return token;
}