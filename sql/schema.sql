CREATE DATABASE student_form;

USE student_form;

-- 管理员表
CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

-- 表单模板表
CREATE TABLE form_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 表单字段表
CREATE TABLE form_fields (
    id INT AUTO_INCREMENT PRIMARY KEY,
    template_id INT,
    field_name VARCHAR(100) NOT NULL,
    field_type VARCHAR(50) NOT NULL, -- text, radio, select
    options TEXT, -- 用于存储选项（JSON格式）
    field_order INT,
    FOREIGN KEY (template_id) REFERENCES form_templates(id) ON DELETE CASCADE
);

-- 表单数据表
CREATE TABLE form_submissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    template_id INT,
    submission_data JSON, -- JSON格式存储所有表单字段的数据
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES form_templates(id) ON DELETE CASCADE
);