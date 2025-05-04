document.addEventListener('DOMContentLoaded', function() {
    // Authentication check
    const token = sessionStorage.getItem('token');
    if (!token) {
        // Redirect to login page if not authenticated
        window.location.href = 'index.html';
        return;
    }
    
    // Parse JWT to get user info
    const userInfo = parseJwt(token);
    
    // Check token expiration
    if (userInfo.exp && userInfo.exp * 1000 < Date.now()) {
        // Token expired, clear it and redirect to login
        sessionStorage.removeItem('token');
        window.location.href = 'index.html?session=expired';
        return;
    }
    
    // Display user name
    document.getElementById('user-name').textContent = userInfo.username || 'User';
    
    // Setup logout button
    document.getElementById('logout-btn').addEventListener('click', function() {
        // Call the secure logout endpoint to invalidate the token server-side
        fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(() => {
            // Clear token and redirect regardless of response
            sessionStorage.removeItem('token');
            window.location.href = 'index.html?logout=success';
        })
        .catch(error => {
            console.error('Logout error:', error);
            // Clear token and redirect anyway
            sessionStorage.removeItem('token');
            window.location.href = 'index.html?logout=success';
        });
    });
    
    // Handle change password button
    const passwordModal = document.getElementById('password-modal');
    if (passwordModal) {
        document.getElementById('change-password-btn').addEventListener('click', function() {
            passwordModal.style.display = 'block';
        });
        
        document.getElementById('cancel-password-change').addEventListener('click', function() {
            passwordModal.style.display = 'none';
        });
        
        document.getElementById('change-password-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            // Simple validation
            if (newPassword !== confirmPassword) {
                document.getElementById('confirm-password-error').textContent = 'Passwords do not match';
                return;
            }
            
            // Send password change request
            fetch('/api/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ currentPassword, newPassword })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    passwordModal.style.display = 'none';
                    showSuccess('Password changed successfully');
                } else {
                    document.getElementById('current-password-error').textContent = data.error || 'Failed to change password';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('current-password-error').textContent = 'An error occurred';
            });
        });
    }
    
    // Load users button (for admins only)
    const loadUsersBtn = document.getElementById('load-users-btn');
    if (loadUsersBtn) {
        // Only display button for admins
        loadUsersBtn.style.display = userInfo.isAdmin ? 'block' : 'none';
        
        loadUsersBtn.addEventListener('click', function() {
            // Secure the request with JWT token - server will verify admin status
            fetch('/api/admin/users', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
            .then(response => {
                if (response.status === 403) {
                    throw new Error('Access denied: Admin privileges required');
                }
                if (!response.ok) {
                    throw new Error('Failed to load users');
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    showError(data.error);
                    return;
                }
                
                const userList = document.getElementById('user-list');
                userList.innerHTML = '';
                
                data.users.forEach(user => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${user.id}</td>
                        <td>${escapeHTML(user.username)}</td>
                        <td>${escapeHTML(user.email)}</td>
                        <td>${user.is_admin ? 'Yes' : 'No'}</td>
                    `;
                    userList.appendChild(row);
                });
            })
            .catch(error => {
                console.error('Error:', error);
                showError(error.message || 'Failed to load users');
            });
        });
    }
    
    // Helper function to parse JWT token
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
            return {};
        }
    }
    
    // Helper function for XSS prevention
    function escapeHTML(str) {
        return str.replace(/[&<>"']/g, function(match) {
            return {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[match];
        });
    }
    
    // Show error message
    function showError(message) {
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 5000);
        }
    }
    
    // Show success message
    function showSuccess(message) {
        const successElement = document.getElementById('success-message');
        if (successElement) {
            successElement.textContent = message;
            successElement.style.display = 'block';
            setTimeout(() => {
                successElement.style.display = 'none';
            }, 5000);
        }
    }
});