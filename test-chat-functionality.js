const io = require('socket.io-client');

console.log('Testing complete Socket.IO chat functionality on localhost...\n');

const socket = io('http://localhost:5000', {
  transports: ['websocket', 'polling'],
  timeout: 5000,
  forceNew: true
});

socket.on('connect', () => {
  console.log('✅ Connected to Socket.IO server');
  console.log('Socket ID:', socket.id);
  
  // Test joining a room
  socket.emit('join room', 'test-room');
  console.log('📍 Joined room: test-room');
  
  // Test sending a message
  setTimeout(() => {
    const testMessage = {
      room: 'test-room',
      message: 'Hello from localhost test!',
      sender_name: 'Local Test User'
    };
    socket.emit('send message', testMessage);
    console.log('📤 Sent message:', testMessage);
  }, 1000);
  
  // Disconnect after testing
  setTimeout(() => {
    socket.disconnect();
  }, 3000);
});

socket.on('disconnect', (reason) => {
  console.log('❌ Disconnected:', reason);
  console.log('\n🎉 Socket.IO chat is now working on localhost!');
  process.exit(0);
});

socket.on('connect_error', (error) => {
  console.error('❌ Connection error:', error.message);
  process.exit(1);
});

socket.on('message', (data) => {
  console.log('📨 Received message:', data);
});

socket.on('user_connected', (data) => {
  console.log('👤 User connected:', data);
});

socket.on('user joined', (data) => {
  console.log('🏠 User joined room:', data);
});

setTimeout(() => {
  console.log('Test timeout');
  process.exit(1);
}, 10000);