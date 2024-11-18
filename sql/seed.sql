USE student_form;

-- 插入管理员
INSERT INTO admins (username, password) VALUES ('admin', '$2b$10$Q0XDAx3.o/Z8ql7ZI.XcRulOr7IbVlnDQ9BRD6lFzv5Ec4uRSwfwe'); -- 密码为 'password' 的哈希值

-- 插入测试表单模板和字段
INSERT INTO form_templates (name) VALUES ('Test Form');
INSERT INTO form_fields (template_id, field_name, field_type, options, field_order) VALUES
(1, 'Student Name', 'text', NULL, 1),
(1, 'Parent Name', 'text', NULL, 2),
(1, 'Phone', 'text', NULL, 3),
(1, 'Grade', 'select', '["Grade 1", "Grade 2", "Grade 3"]', 4);