-- Quick CASCADE DELETE Setup for HRMC
-- Execute these commands one by one to add cascade delete constraints

-- ==================================================
-- CORE USER-RELATED CASCADES
-- ==================================================

-- 1. Leave Requests → Users (when user deleted, remove all leave requests)
ALTER TABLE leave_request 
ADD CONSTRAINT fk_leave_request_user_cascade 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 2. Attendance → Users (when user deleted, remove all attendance)  
ALTER TABLE attendance 
ADD CONSTRAINT fk_attendance_user_cascade 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 3. Refresh Tokens → Users (when user deleted, remove tokens)
ALTER TABLE refresh_tokens 
ADD CONSTRAINT fk_refresh_tokens_user_cascade 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 4. Certificate Requests → Users (when user deleted, remove cert requests)
ALTER TABLE certificate_requests 
ADD CONSTRAINT fk_certificate_requests_user_cascade 
FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- ==================================================
-- EVALUATION SYSTEM CASCADES
-- ==================================================

-- 5. Evaluations → Users (when teacher deleted, remove their evaluations)
ALTER TABLE evaluation 
ADD CONSTRAINT fk_evaluation_teacher_cascade 
FOREIGN KEY (teacher_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 6. Evaluation Answers → Evaluations (when evaluation deleted, remove answers)
ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_eval_cascade 
FOREIGN KEY (evaluation_id) REFERENCES evaluation(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 7. Evaluation Answers → Users (when student deleted, remove their answers)
ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_student_cascade 
FOREIGN KEY (student_id) REFERENCES users(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- 8. Evaluation Answers → Questions (when question deleted, remove related answers)
ALTER TABLE evaluation_answers 
ADD CONSTRAINT fk_evaluation_answers_question_cascade 
FOREIGN KEY (question_id) REFERENCES evaluation_questions(id) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- ==================================================
-- ORGANIZATIONAL CASCADES (SET NULL INSTEAD OF DELETE)
-- ==================================================

-- 9. Users → Roles (when role deleted, set user role to NULL)
ALTER TABLE users 
ADD CONSTRAINT fk_users_role_setnull 
FOREIGN KEY (role_id) REFERENCES roles(id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- 10. Users → Departments (when department deleted, set user department to NULL)
ALTER TABLE users 
ADD CONSTRAINT fk_users_department_setnull 
FOREIGN KEY (department_id) REFERENCES department(id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- ==================================================
-- VERIFICATION
-- ==================================================

-- Check all foreign keys with cascade behavior
SELECT 
    CONCAT(TABLE_NAME, '.', COLUMN_NAME) as 'Column',
    CONCAT(REFERENCED_TABLE_NAME, '.', REFERENCED_COLUMN_NAME) as 'References',
    DELETE_RULE as 'On Delete',
    UPDATE_RULE as 'On Update',
    CONSTRAINT_NAME as 'Constraint Name'
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = DATABASE() 
AND REFERENCED_TABLE_NAME IS NOT NULL
AND (DELETE_RULE = 'CASCADE' OR DELETE_RULE = 'SET NULL')
ORDER BY TABLE_NAME;