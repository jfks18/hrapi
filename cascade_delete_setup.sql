-- HRMC Database CASCADE DELETE Setup
-- This script adds foreign key constraints with ON DELETE CASCADE
-- Based on the relationships identified in server.js

-- ==================================================
-- STEP 1: Drop existing foreign keys (if any)
-- ==================================================

-- Note: You may need to check existing constraint names first with:
-- SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
-- WHERE TABLE_SCHEMA = 'your_database_name' AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Example drops (adjust constraint names as needed):
-- ALTER TABLE users DROP FOREIGN KEY fk_users_role;
-- ALTER TABLE users DROP FOREIGN KEY fk_users_department;

-- ==================================================
-- STEP 2: Add CASCADE DELETE Foreign Keys
-- ==================================================

-- Users table foreign keys
ALTER TABLE users 
ADD CONSTRAINT fk_users_role 
FOREIGN KEY (role_id) REFERENCES roles(id) 
ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE users 
ADD CONSTRAINT fk_users_department 
FOREIGN KEY (department_id) REFERENCES department(id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- Leave Request foreign keys
ALTER TABLE leave_request 
ADD CONSTRAINT fk_leave_request_user 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Attendance foreign keys
ALTER TABLE attendance 
ADD CONSTRAINT fk_attendance_user 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Refresh Tokens foreign keys
ALTER TABLE refresh_tokens 
ADD CONSTRAINT fk_refresh_tokens_user 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Evaluation foreign keys
ALTER TABLE evaluation 
ADD CONSTRAINT fk_evaluation_teacher 
FOREIGN KEY (teacher_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE evaluation 
ADD CONSTRAINT fk_evaluation_student 
FOREIGN KEY (student_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Evaluation Answers foreign keys
ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_evaluation 
FOREIGN KEY (evaluation_id) REFERENCES evaluation(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_question 
FOREIGN KEY (question_id) REFERENCES evaluation_questions(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_student 
FOREIGN KEY (student_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Evaluation Questions foreign keys (if evaluation_id exists)
-- Note: Based on server.js, there might be two types of questions:
-- 1. General questions (no evaluation_id)
-- 2. Evaluation-specific questions (with evaluation_id)
-- Uncomment the following if evaluation_questions has evaluation_id column:
-- ALTER TABLE evaluation_questions 
-- ADD CONSTRAINT fk_evaluation_questions_evaluation 
-- FOREIGN KEY (evaluation_id) REFERENCES evaluation(id) 
-- ON DELETE CASCADE ON UPDATE CASCADE;

-- Certificate Requests foreign keys
ALTER TABLE certificate_requests 
ADD CONSTRAINT fk_certificate_requests_user 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- System Logs foreign keys (if user_id exists)
-- ALTER TABLE system_logs 
-- ADD CONSTRAINT fk_system_logs_user 
-- FOREIGN KEY (user_id) REFERENCES users(id) 
-- ON DELETE SET NULL ON UPDATE CASCADE;

-- Chat Messages foreign keys (if chat functionality exists)
-- ALTER TABLE chat_messages 
-- ADD CONSTRAINT fk_chat_messages_user 
-- FOREIGN KEY (user_id) REFERENCES users(id) 
-- ON DELETE CASCADE ON UPDATE CASCADE;

-- ==================================================
-- STEP 3: Verification Queries
-- ==================================================

-- Check all foreign key constraints
SELECT 
    TABLE_NAME,
    COLUMN_NAME,
    CONSTRAINT_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME,
    DELETE_RULE,
    UPDATE_RULE
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = DATABASE() 
AND REFERENCED_TABLE_NAME IS NOT NULL
ORDER BY TABLE_NAME, COLUMN_NAME;

-- ==================================================
-- STEP 4: Test CASCADE DELETE (DANGEROUS - USE WITH CAUTION!)
-- ==================================================

-- WARNING: These are destructive operations for testing only
-- Uncomment and modify ONLY in a test environment

/*
-- Test 1: Create a test user
INSERT INTO users (id, name, email, password, role_id, department_id, code, created_at) 
VALUES ('test123', 'Test User', 'test@test.com', 'hashedpass', '1', '1', 'T123', NOW());

-- Test 2: Create dependent records
INSERT INTO attendance (user_id, date, status) VALUES ('test123', CURDATE(), 'Present');
INSERT INTO leave_request (user_id, type, start_date, end_date, reason) 
VALUES ('test123', 'Sick', CURDATE(), CURDATE(), 'Testing cascade');

-- Test 3: Delete user and verify cascade
-- This should automatically delete all related records
DELETE FROM users WHERE id = 'test123';

-- Test 4: Verify cleanup
SELECT 'attendance' as table_name, COUNT(*) as records FROM attendance WHERE user_id = 'test123'
UNION ALL
SELECT 'leave_request', COUNT(*) FROM leave_request WHERE user_id = 'test123'
UNION ALL  
SELECT 'users', COUNT(*) FROM users WHERE id = 'test123';
-- All counts should be 0
*/

-- ==================================================
-- NOTES AND RECOMMENDATIONS
-- ==================================================

/*
CASCADE DELETE BEHAVIOR SUMMARY:

1. When a USER is deleted:
   ✓ All attendance records → DELETED
   ✓ All leave requests → DELETED  
   ✓ All refresh tokens → DELETED
   ✓ All evaluations (as teacher/student) → DELETED
   ✓ All evaluation answers → DELETED
   ✓ All certificate requests → DELETED
   ✓ Role/Department references → SET NULL

2. When a ROLE is deleted:
   ✓ User role_id → SET NULL (users keep their accounts)

3. When a DEPARTMENT is deleted:
   ✓ User department_id → SET NULL (users keep their accounts)

4. When an EVALUATION is deleted:
   ✓ All related evaluation_answers → DELETED

5. When an EVALUATION_QUESTION is deleted:
   ✓ All related evaluation_answers → DELETED

IMPORTANT CONSIDERATIONS:
- CASCADE DELETE is powerful but dangerous
- Always backup before implementing
- Consider soft deletes (status flags) for important data
- Test thoroughly in a development environment
- Monitor for orphaned data after implementation
- Consider adding audit trails for deleted records

ALTERNATIVE APPROACH - SOFT DELETES:
Instead of CASCADE DELETE, consider adding a 'deleted_at' timestamp column
to important tables and filtering out soft-deleted records in queries.
*/