document.addEventListener('DOMContentLoaded', function() {
    const messageElement = document.getElementById('message');
    const requestResetForm = document.getElementById('request-reset-form');
    const verifyTokenForm = document.getElementById('verify-token-form');
    const resetPasswordForm = document.getElementById('reset-password-form');
    
    // Check if user is already logged in
    if (sessionStorage.getItem('token')) {
        window.location.href = 'admin.html';
        return;
    }
    
    // Helper function to show messages
    function showMessage(message, isError = false) {
        messageElement.textContent = message;
        messageElement.className = isError ? 'message error-message' : 'message success-message';
    }
    
    // Step 1: Handle password reset request
    requestResetForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        if (!email || !validateEmail(email)) {
            showMessage('Please enter a valid email address', true);
            return;
        }
        
        // Disable the submit button
        const submitButton = requestResetForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner"></span> Sending...';
        
        fetch('/api/reset-password-request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email })
        })
        .then(response => response.json())
        .then(data => {
            submitButton.disabled = false;
            submitButton.textContent = 'Request Reset Token';
            
            if (data.success) {
                showMessage('A reset token has been sent to your email. For demo purposes, check the server console for the token.');
                
                // Hide request form and show verify token form
                requestResetForm.style.display = 'none';
                verifyTokenForm.style.display = 'block';
                
                // Pre-fill email field
                document.getElementById('verify-email').value = email;
            } else {
                showMessage(data.error || 'An error occurred', true);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            submitButton.disabled = false;
            submitButton.textContent = 'Request Reset Token';
            showMessage('Failed to request password reset.', true);
        });
    });
    
    // Step 2: Handle token verification
    verifyTokenForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const email = document.getElementById('verify-email').value;
        const token = document.getElementById('token').value;
        
        if (!token) {
            document.getElementById('token-error').textContent = 'Token is required';
            return;
        }
        
        // Disable the submit button
        const submitButton = verifyTokenForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner"></span> Verifying...';
        
        // Actually verify the token with the server
        fetch('/api/verify-reset-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, token })
        })
        .then(response => response.json())
        .then(data => {
            submitButton.disabled = false;
            submitButton.textContent = 'Verify Token';
            
            if (data.success) {
                showMessage('Token verified. Please set your new password.');
                
                // Hide verify form and show password reset form
                verifyTokenForm.style.display = 'none';
                resetPasswordForm.style.display = 'block';
                
                // Pre-fill fields
                document.getElementById('reset-email').value = email;
                document.getElementById('reset-token').value = token;
            } else {
                showMessage(data.error || 'Invalid token. Please try again.', true);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            submitButton.disabled = false;
            submitButton.textContent = 'Verify Token';
            showMessage('Failed to verify token.', true);
        });
    });
    
    // Step 3: Handle password reset
    resetPasswordForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const email = document.getElementById('reset-email').value;
        const token = document.getElementById('reset-token').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-new-password').value;
        
        // Basic validation
        if (newPassword.length < 8) {
            document.getElementById('new-password-error').textContent = 'Password must be at least 8 characters';
            return;
        }
        
        if (newPassword !== confirmPassword) {
            document.getElementById('confirm-password-error').textContent = 'Passwords do not match';
            return;
        }
        
        // Disable the submit button
        const submitButton = resetPasswordForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner"></span> Resetting...';
        
        fetch('/api/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, token, newPassword })
        })
        .then(response => response.json())
        .then(data => {
            submitButton.disabled = false;
            submitButton.textContent = 'Reset Password';
            
            if (data.success) {
                showMessage('Password has been updated successfully! Redirecting to login...');
                
                // Redirect to login page after a short delay
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 2000);
            } else {
                showMessage(data.error || 'Failed to reset password.', true);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            submitButton.disabled = false;
            submitButton.textContent = 'Reset Password';
            showMessage('Failed to reset password.', true);
        });
    });
    
    // Utility functions
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    // Password strength meter
    const newPasswordInput = document.getElementById('new-password');
    const passwordStrength = document.getElementById('password-strength');
    
    if (newPasswordInput && passwordStrength) {
        newPasswordInput.addEventListener('input', function() {
            const password = this.value;
            const strength = calculatePasswordStrength(password);
            
            // Update the strength meter
            passwordStrength.className = 'password-strength';
            if (password.length === 0) {
                passwordStrength.style.display = 'none';
            } else {
                passwordStrength.style.display = 'block';
                if (strength < 30) {
                    passwordStrength.classList.add('weak');
                } else if (strength < 60) {
                    passwordStrength.classList.add('medium');
                } else if (strength < 80) {
                    passwordStrength.classList.add('strong');
                } else {
                    passwordStrength.classList.add('very-strong');
                }
            }
        });
    }
    
    // Password strength calculator
    function calculatePasswordStrength(password) {
        let strength = 0;
        
        // Length
        if (password.length >= 8) strength += 20;
        if (password.length >= 12) strength += 20;
        
        // Contains both lower and uppercase
        if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength += 20;
        
        // Contains numbers
        if (password.match(/\d/)) strength += 20;
        
        // Contains special chars
        if (password.match(/[^a-zA-Z\d]/)) strength += 20;
        
        return strength;
    }
});