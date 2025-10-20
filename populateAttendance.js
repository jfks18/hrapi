// populateAttendance.js
// Reads attendanceData.json and inserts 10 records into the /attendance API
const fs = require('fs');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_URL = 'http://localhost:5000/attendance';

async function populateAttendance() {
  const data = JSON.parse(fs.readFileSync('attendanceData.json', 'utf8'));
  for (let i = 0; i < data.length; i++) {
    const record = data[i];
    try {
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(record)
      });
      const result = await res.json();
      console.log(`Inserted record ${i + 1}:`, result);
    } catch (err) {
      console.error(`Error inserting record ${i + 1}:`, err);
    }
  }
}

populateAttendance();
