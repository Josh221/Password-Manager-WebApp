# Secure Password Manager 🔐

This is a secure password manager application built with Flask, designed to help users store, manage, and retrieve passwords safely. The application prioritizes data security and user experience by leveraging modern web development and encryption techniques.

## Features ✨

**User Registration & Authentication:**

Users can create accounts with hashed passwords using werkzeug.security and log in securely.

**Encrypted Password Storage:**

Passwords for websites are encrypted with cryptography.fernet before being stored in the database and are decrypted only when retrieved.

**Search & Retrieve Passwords:**

Users can search for stored passwords by website, with encrypted passwords decrypted only after authentication.

**CSRF Protection:**

Built-in protection against cross-site request forgery attacks using Flask-WTF.

**Session Security:**

Sessions are secured with features like secure cookies, HttpOnly, and a session timeout to protect user data.

**Relational Database:**

User and password data are stored in a SQLite database, managed with SQLAlchemy for efficient querying and relationships.

## Technologies Used 🛠️

Framework: Flask

Database: SQLite with SQLAlchemy ORM

Encryption: cryptography.fernet for password encryption

Form Validation: Flask-WTF

Session Management: Flask sessions with secure configurations

Frontend: HTML and Bootstrap for templates

## How It Works ⚙️

**Sign Up:**

Users create an account with a unique username and secure password.

**Log In:**

Existing users can log in to access their stored passwords.

**Add Passwords:**

Users can securely store passwords for websites along with associated usernames/emails. Passwords are encrypted before being saved in the database.

**Search Passwords:**

Users can search for saved credentials by entering the website name. The decrypted password is displayed securely if found.

**Log Out:**

Users can log out to end their session, ensuring their data remains secure.

## Future Enhancements 🚀

Add password strength validation during sign-up and password addition.

Implement multi-factor authentication for added security.

Add rate limiting to the login endpoint to prevent brute force attacks.

Allow users to export and import passwords securely.

