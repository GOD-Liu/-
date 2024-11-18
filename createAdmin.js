const mysql = require('mysql');
const bcrypt = require('bcrypt');

// 数据库连接
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456', // 替换为您的数据库密码
    database: 'student_form'
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL database.');
});

const username = 'admin'; // 设置新的管理员用户名
const plainPassword = 'Admin123'; // 设置新的管理员密码

// 对密码进行哈希处理
bcrypt.hash(plainPassword, 10, (err, hash) => {
    if (err) throw err;

    // 插入新管理员到数据库
    const sql = 'INSERT INTO admins (username, password) VALUES (?, ?)';
    db.query(sql, [username, hash], (err, result) => {
        if (err) throw err;
        console.log('Admin account created successfully!');
        db.end();
    });
});