-- Remove Foreign Key Constraint from evaluation_answers table
-- This will allow insertion of evaluation_answers without strict student_id validation

-- Step 1: Check existing constraints on evaluation_answers table
SELECT 
    CONSTRAINT_NAME,
    COLUMN_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = DATABASE() 
AND TABLE_NAME = 'evaluation_answers'
AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Step 2: Drop the specific foreign key constraint causing the issue
-- Based on the error message, the constraint name is 'fk_evaluation_answers_student'
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_student;

-- Step 3: Verify the constraint has been removed
SELECT 
    CONSTRAINT_NAME,
    COLUMN_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = DATABASE() 
AND TABLE_NAME = 'evaluation_answers'
AND REFERENCED_TABLE_NAME IS NOT NULL;

-- Optional: If you want to remove ALL foreign key constraints from evaluation_answers table
-- Uncomment the lines below:

/*
-- Remove evaluation constraint (if exists)
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_evaluation;

-- Remove question constraint (if exists)  
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_question;

-- Remove evaluation answers eval cascade constraint (if exists)
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_eval_cascade;

-- Remove evaluation answers question cascade constraint (if exists)
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_question_cascade;

-- Remove evaluation answers student cascade constraint (if exists)
ALTER TABLE evaluation_answers 
DROP FOREIGN KEY fk_evaluation_answers_student_cascade;
*/

-- Note: After removing constraints, you can insert evaluation_answers with any student_id
-- even if that student_id doesn't exist in the users table
-- This provides more flexibility but removes referential integrity