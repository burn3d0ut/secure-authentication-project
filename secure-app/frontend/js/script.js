document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    
    // Check token validity on page load
    checkAuthentication();
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // Validate input
            if (!username || !password) {
                showError('Username and password are required');
                return;
            }
            
            // Disable the login button during request
            const submitButton = loginForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner"></span> Logging in...';
            
            // this sends login request
            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // SECURE: Store JWT token in sessionStorage (more secure than localStorage)
                    // For even better security, use httpOnly cookies in production
                    sessionStorage.setItem('token', data.token);
                    
                    // Parse the token to get user info (without storing the whole user object)
                    const userInfo = parseJwt(data.token);
                    
                    // Store token issue time for potential token refresh
                    sessionStorage.setItem('token_issued_at', Date.now());
                    
                    // redirect to admin dashboard
                    window.location.href = 'admin.html';
                } else {
                    // it displays error message
                    showError(data.error || 'Invalid login credentials');
                    
                    // Re-enable login button
                    submitButton.disabled = false;
                    submitButton.textContent = 'Login';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showError('An error occurred during login');
                
                // Re-enable login button
                submitButton.disabled = false;
                submitButton.textContent = 'Login';
            });
        });
    }
    
    // Function to show error message
    function showError(message) {
        if (errorMessage) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
        }
    }
    
    // Function to parse JWT token
    function parseJwt(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error('Error parsing JWT', e);
            return null;
        }
    }
    
    // Function to check if the user is authenticated
    function checkAuthentication() {
        const token = sessionStorage.getItem('token');
        // If on login page and already authenticated, redirect to admin
        if (token && window.location.pathname.endsWith('index.html')) {
            window.location.href = 'admin.html';
        }
    }
});