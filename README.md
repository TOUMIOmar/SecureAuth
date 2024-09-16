# User Authentication Backend

This repository provides a reusable backend solution for user authentication, including user sign-up, sign-in, and authentication using Google and Facebook. It is built using Express.js and Mongoose, with robust security features and middleware for sanitization and validation.

## Features

- User sign-up and sign-in
- Sign-up/sign-in using Google and Facebook OAuth
- Middleware for token verification
- Secure password hashing
- Protection against NoSQL injection and XSS attacks
- Environment-based configuration

## Tech Stack

- Node.js
- Express.js
- MongoDB & Mongoose
- JWT (JSON Web Token)
- Google APIs
- Facebook API
- dotenv
- express-mongo-sanitize
- xss-clean
- bcrypt
- morgan
- cors

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/TOUMIOmar/SecureAuth
    ```

2. **Navigate to the project directory:**
    ```bash
    cd SecureAuth

    ```

3. **Install the dependencies:**
    ```bash
    npm install
    ```

4. **Create a `.env` file in the root directory and add the following environment variables:**
    ```env
    NODE_ENV=development
    REMOTE=your_remote_url
    JWT_SECRET=your_jwt_secret
    GOOGLE_CLIENT_ID=your_google_client_id
    GOOGLE_CLIENT_SECRET=your_google_client_secret
    ```

## Usage

1. **Start the server:**
    ```bash
    npm start
    ```

2. **The server will start running on `http://localhost:3000` (or the port specified in your environment variables).**

## API Endpoints

### Authentication Routes

- **Google Authentication**
    - `GET /api/v1/auth/google`
- **Sign Up**
    - `POST /api/v1/auth/signup`
- **Sign In**
    - `POST /api/v1/auth/signin`
- **Sign In Admin**
    - `POST /api/v1/auth/admin/signin`
- **Update Profile**
    - `PUT /api/v1/auth/updateprofile`
- **Forget Password**
    - `POST /api/v1/auth/forgetpassword`
- **Reset Password**
    - `POST /api/v1/auth/resetpassword`
- **Facebook Authentication**
    - `POST /api/v1/auth/facebook`

### Middleware

- **userMiddleware**: Middleware for verifying the JWT token to protect routes.

### Models

- **User**: Mongoose model with fields like name, email, password, phone number, etc. Includes password hashing and validation.

## Security

- **Data Sanitization**: `express-mongo-sanitize` and `xss-clean` are used to prevent NoSQL injection and XSS attacks.
- **Rate Limiting**: Configured to limit the number of requests to prevent DDoS attacks.
- **CORS**: Configured to allow cross-origin requests from a specified remote URL.

## Contributions

Feel free to submit pull requests or open issues to contribute to this project.


