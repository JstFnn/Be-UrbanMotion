# Backend UrbanMotion

## Getting Started

### Step 1: Clone the Repository

First, clone this repository to your local machine. You’re just a few steps away from using the app!

### Step 2: Install Dependencies

Run the following command to install all necessary packages:

```bash
npm install
```

### Step 3: Set Up Your `.env` File

Locate the .env.sample file in the project’s root directory. Rename it to .env and configure the necessary environment variables (e.g., database connection strings, API keys).

### Step 4: Run Migrations and Seed the Database
Ensure your database is up and running, then execute the following commands:
1. Run Migrations:
   ```bash
    npm run migration-up
    ```
2. Seed the Database :
      ```bash
    npm run seed-up
    ```
### Step 5: Launch the App
Once the setup is complete, you can start the app by running:

```bash
npm run dev
```
This will start the app in development mode.

### Step 6: Enjoy

Your app will be accessible at http://localhost:5000 or the port specified in your .env file. Dive in and explore all the features