document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');
    
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            //Disable the login button during request
            const submitButton = loginForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = 'Logging in...';
            
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
                    // store user data in localStorage (vulnerable)
                    localStorage.setItem('user', JSON.stringify(data.user));
                    
                    // redirect to admin dashboard
                    window.location.href = 'admin.html';
                } else {
                    // it displays error message
                    errorMessage.textContent = data.error || 'Invalid login credentials';
                    errorMessage.style.display = 'block';
                    
                    // Re-enable login button
                    submitButton.disabled = false;
                    submitButton.textContent = 'Login';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                errorMessage.textContent = 'An error occurred during login';
                errorMessage.style.display = 'block';
                
                // Re-enable login button
                submitButton.disabled = false;
                submitButton.textContent = 'Login';
            });
        });
    }
    
    // checks username availability (for user enumeration demo)
    const usernameInput = document.getElementById('username');
    if (usernameInput) {
        usernameInput.addEventListener('blur', function() {
            const username = usernameInput.value.trim();
            if (username) {
                fetch('/api/check-username', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.exists) {
                        console.log(`Username "${username}" exists`);
                        // vulnerability: Giving feedback about username existence
                        usernameInput.style.borderColor = '#28a745';
                    } else {
                        console.log(`Username "${username}" does not exist`);
                        usernameInput.style.borderColor = '#dc3545';
                    }
                })
                .catch(error => {
                    console.error('Error checking username:', error);
                });
            }
        });
    }
});