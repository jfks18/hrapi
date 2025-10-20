// createUser.js
// This script creates a user by calling the /users endpoint of your API
require('dotenv').config();
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { v4: uuidv4 } = require('uuid');


const API_URL = 'http://localhost:5000/users';

const API_TOKEN = process.env.API_TOKEN; // Loaded from .env

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function ask(question) {
  return new Promise(resolve => rl.question(question, answer => resolve(answer)));
}

async function createUser() {
  const name = await ask('Enter name: ');
  const email = await ask('Enter email: ');
  const password = await ask('Enter password: ');
  const code = await ask('Enter code: ');
  rl.close();

  const user = {
    id: uuidv4(),
    name,
    email,
    password,
    code,
    role_id: null, // role is null
    department_id: null  
  };

  const res = await fetch(API_URL, {
    method: 'POST',
    headers: {
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${API_TOKEN}`,
  'ngrok-skip-browser-warning': 'true'
    },
    body: JSON.stringify(user)
  });

  const data = await res.json();
  console.log('Response:', data);
}

createUser();
