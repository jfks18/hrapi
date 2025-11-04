const io = require('socket.io-client');

console.log('Testing Socket.IO connection without token (should fail)...');

// Test 1: Connection without token (should fail with JWT_SECRET set)
const socketWithoutToken = io('http://localhost:5000', {
  transports: ['websocket', 'polling'],
  timeout: 5000,
  forceNew: true
});

socketWithoutToken.on('connect', () => {
  console.log('✅ Connected without token - Socket ID:', socketWithoutToken.id);
  socketWithoutToken.disconnect();
  testWithToken();
});

socketWithoutToken.on('connect_error', (error) => {
  console.log('❌ Failed to connect without token (expected):', error.message);
  socketWithoutToken.disconnect();
  testWithToken();
});

function testWithToken() {
  console.log('\nTesting Socket.IO connection with dummy token...');
  
  // Test 2: Connection with a dummy token (should also fail with invalid token)
  const socketWithToken = io('http://localhost:5000', {
    transports: ['websocket', 'polling'],
    timeout: 5000,
    forceNew: true,
    auth: {
      token: 'dummy-token'
    }
  });

  socketWithToken.on('connect', () => {
    console.log('✅ Connected with token - Socket ID:', socketWithToken.id);
    socketWithToken.disconnect();
    process.exit(0);
  });

  socketWithToken.on('connect_error', (error) => {
    console.log('❌ Failed to connect with invalid token (expected):', error.message);
    socketWithToken.disconnect();
    console.log('\n🔍 Solution: Your frontend needs to send a valid JWT token or you need to modify the authentication middleware for local development.');
    process.exit(0);
  });
}

setTimeout(() => {
  console.log('Test timeout');
  process.exit(1);
}, 10000);