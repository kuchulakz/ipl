function login() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    console.log('Login Function Called');
    console.log('Login Username:', username);
    console.log('Login Password:', password);

    if (username === '') {
        console.error('Username should not be empty');
        alert('Username should not be empty');
        return;
    }

    if (password === '') {
        console.error('Password should not be empty');
        alert('Password should not be empty');
        return;
    }

    // Log the login information
    console.log('Login: ', { username: username, password: password });
}

function register() {
    const name = document.getElementById('registerName').value;
    const email = document.getElementById('registerEmail').value;
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    console.log('Register Function Called');
    console.log('Register Name:', name);
    console.log('Register Email:', email);
    console.log('Register Username:', username);
    console.log('Register Password:', password);

    if (name === '' || email === '' || username === '' || password === '') {
        console.error('All fields are required.');
        alert('All fields are required.');
        return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
        console.error('Please enter a valid email address.');
        alert('Please enter a valid email address.');
        return;
    }

    const usernamePattern = /^[a-zA-Z0-9]+$/;
    if (!usernamePattern.test(username)) {
        console.error('Username must be alphanumeric and cannot contain special characters.');
        alert('Username must be alphanumeric and cannot contain special characters.');
        return;
    }

    const passwordPattern = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!passwordPattern.test(password)) {
        console.error('Password must be at least 8 characters long, contain at least one uppercase letter, and one number.');
        alert('Password must be at least 8 characters long, contain at least one uppercase letter, and one number.');
        return;
    }

    // Log the registration information
    console.log('Register: ', { name: name, email: email, username: username, password: password });
}

module.exports = { login, register };
