const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const xl = require('excel4node');
const bodyParser = require('body-parser');
const QRCode = require('qrcode');
const QRCodeSVG = require('qrcode-svg');
const multer = require('multer');
const fs = require('fs');
const iconv = require('iconv-lite');
const formidable = require('formidable'); // 编码解析
const svgCaptcha = require('svg-captcha'); // 验证码

const app = express();
const port = 3000;

// MySQL数据库连接
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'student_form',
	charset: 'utf8mb4'
});

db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL database.');
});

// Express session中间件
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 设置为 true 时，仅在 HTTPS 连接上发送 cookie
}));

app.use(express.urlencoded({ extended: true, limit: '10mb', parameterLimit: 50000, defaultCharset: 'utf-8' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.json({ limit: '10mb', type: 'application/json', defaultCharset: 'utf-8' }));
app.use(bodyParser.text({ type: 'application/x-www-form-urlencoded', limit: '10mb' }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// 设置 multer 用于文件上传
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname)); // 使用当前时间戳命名文件
    }
});

const upload = multer({ storage: storage });

// 生成验证码
app.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create({
        size: 4, // 字符数量
        ignoreChars: '0o1i', // 忽略容易混淆的字符
        noise: 1, // 减少干扰线数量
        color: true, // 使用彩色字体
        background: '#e0f7fa', // 浅蓝色背景
        width: 120, // 验证码图片的宽度
        height: 50, // 验证码图片的高度
        fontSize: 48, // 字体大小
    });

    // 使用正则表达式更精确地替换字母的颜色，只替换与字母相关的 fill 属性
    const captchaSVG = captcha.data.replace(/<text.*?fill="#\w{6}"/g, 'fill="#2a4d69"');

    req.session.captcha = captcha.text; // 将验证码文本存储在会话中
    res.type('svg');
    res.status(200).send(captchaSVG);
});

// 验证验证码的路由
app.post('/verify-captcha', (req, res) => {
    const { captcha } = req.body;
    const isValid = req.session.captcha && captcha.toLowerCase() === req.session.captcha.toLowerCase();
    res.json({ valid: isValid });
});

// 管理员登录页面
app.get('/login', (req, res) => {
    res.render('login', { errorMessage: null });
});

// 登录处理
app.post('/login', (req, res) => {
    const { username, password, captcha } = req.body;

    // 验证验证码是否正确（不区分大小写）
    if (req.session.captcha && captcha.toLowerCase() !== req.session.captcha.toLowerCase()) {
        return res.render('login', { errorMessage: '验证码错误，请重新输入！' });
    }

    // 验证用户名和密码逻辑
    if (username && password) {
        db.query('SELECT * FROM admins WHERE username = ?', [username], (err, results) => {
            if (err) {
                return res.render('login', { errorMessage: '数据库查询错误，请稍后再试。' });
            }

            if (results.length > 0) {
                bcrypt.compare(password, results[0].password, (err, isMatch) => {
                    if (err) {
                        return res.render('login', { errorMessage: '密码验证错误，请稍后再试。' });
                    }

                    if (isMatch) {
                        req.session.loggedin = true;
                        req.session.username = username;
                        res.redirect('/admin');
                    } else {
                        res.render('login', { errorMessage: '密码错误，请重新输入！' });
                    }
                });
            } else {
                res.render('login', { errorMessage: '用户名不存在，请重新输入！' });
            }
        });
    } else {
        res.render('login', { errorMessage: '请输入用户名和密码！' });
    }
});

app.get('/admin', (req, res) => {
    if (req.session.loggedin) {
        res.redirect('/admin/forms'); // 或者渲染一个仪表板页面
    } else {
        res.redirect('/login');
    }
});

// 发布表单
app.post('/admin/forms/:id/publish', (req, res) => {
    const formId = req.params.id;

    db.query('UPDATE form_templates SET status = ? WHERE id = ?', ['published', formId], (err, result) => {
        if (err) {
            console.error("Error publishing form:", err);
            return res.status(500).send("Error publishing form.");
        }

        res.redirect('/admin/forms');
    });
});

// 停止收集表单
app.post('/admin/forms/:id/close', (req, res) => {
    const formId = req.params.id;

    db.query('UPDATE form_templates SET status = ? WHERE id = ?', ['closed', formId], (err, result) => {
        if (err) {
            console.error("Error closing form:", err);
            return res.status(500).send("Error closing form.");
        }

        res.redirect('/admin/forms');
    });
});




// 表单创建页面
app.get('/admin/forms/create', (req, res) => {
    if (req.session.loggedin) {
        res.render('form_builder', { form: null });
    } else {
        res.redirect('/login');
    }
});

// 处理表单创建请求
app.post('/admin/forms/create', (req, res) => {
    const { form_name, field_name, field_type, options } = req.body;

    if (!form_name || !field_name || !field_type) {
        return res.status(400).send('表单名称、字段名称和字段类型都是必填项。');
    }

    db.query('INSERT INTO form_templates (name, status) VALUES (?, "draft")', [form_name], (err, result) => {
        if (err) {
            console.error("Error inserting form template:", err);
            return res.status(500).send('创建表单时出错。');
        }

        const template_id = result.insertId;
        const fieldPromises = [];

        field_name.forEach((name, index) => {
            const type = field_type[index];
            const opts = options[index] ? JSON.stringify(options[index].split(',')) : null;
            const query = 'INSERT INTO form_fields (template_id, field_name, field_type, options, field_order) VALUES (?, ?, ?, ?, ?)';
            fieldPromises.push(
                new Promise((resolve, reject) => {
                    db.query(query, [template_id, name, type, opts, index], (err, result) => {
                        if (err) {
                            console.error("Error inserting form field:", err);
                            return reject(err);
                        }
                        resolve(result);
                    });
                })
            );
        });

        Promise.all(fieldPromises)
            .then(() => res.redirect('/admin/forms'))
            .catch(err => res.status(500).send('创建表单字段时出错。'));
    });
});

// 显示编辑表单页面
app.get('/admin/forms/:id/edit', (req, res) => {
    if (req.session.loggedin) {
        const formId = req.params.id;

        db.query('SELECT * FROM form_templates WHERE id = ?', [formId], (err, formResults) => {
            if (err) throw err;

            db.query('SELECT * FROM form_fields WHERE template_id = ?', [formId], (err, fieldResults) => {
                if (err) throw err;

                const form = {
                    id: formResults[0].id,
                    name: formResults[0].name,
                    fields: fieldResults.map(field => ({
                        field_name: field.field_name,
                        field_type: field.field_type,
                        options: field.options ? JSON.parse(field.options) : null
                    }))
                };

                res.render('form_builder', { form });
            });
        });
    } else {
        res.redirect('/login');
    }
});

// 处理表单编辑请求
app.post('/admin/forms/:id/edit', (req, res) => {
    const formId = req.params.id;
    const { form_name, field_name, field_type, options } = req.body;

    db.query('UPDATE form_templates SET name = ? WHERE id = ?', [form_name, formId], (err, result) => {
        if (err) throw err;

        db.query('DELETE FROM form_fields WHERE template_id = ?', [formId], (err, result) => {
            if (err) throw err;

            field_name.forEach((name, index) => {
                const type = field_type[index];
                const opts = options[index] ? JSON.stringify(options[index].split(',')) : null;
                db.query('INSERT INTO form_fields (template_id, field_name, field_type, options, field_order) VALUES (?, ?, ?, ?, ?)',
                    [formId, name, type, opts, index], (err, result) => {
                        if (err) throw err;
                    });
            });

            res.redirect('/admin/forms');
        });
    });
});

app.get('/form/:id', async (req, res) => {
    const formId = req.params.id;
    // 从数据库中查询与该表单ID相关的字段信息
    const fields = await new Promise((resolve, reject) => {
        db.query('SELECT * FROM form_fields WHERE template_id = ?', [formId], (err, results) => {
            if (err) return reject(err);
            resolve(results);
        });
    });

    fields.forEach(field => {
        if (field.field_type === 'double_dropdown') {
            // 将 JSON 格式的选项字符串解析为对象
            try {
                field.options = JSON.parse(field.options);
            } catch (err) {
                console.error('Error parsing options for field:', field.field_name, err);
            }
        }
    });

    console.log('Fields data:', fields); // 输出调试信息

    // 渲染表单页面，并传递字段数据
    res.render('form_display', { fields });
});

// 显示所有表单的页面
app.get('/admin/forms', (req, res) => {
    if (req.session.loggedin) {
        const query = `
            SELECT form_templates.id, form_templates.name, form_templates.has_new_submissions, 
                   form_templates.status, 
                   COUNT(form_submissions.id) AS submission_count,
                   SUM(IF(form_submissions.is_read = 0, 1, 0)) AS new_feedback_count -- 获取未读反馈数量
            FROM form_templates
            LEFT JOIN form_submissions ON form_templates.id = form_submissions.template_id
            GROUP BY form_templates.id
        `;
        
        db.query(query, (err, results) => {
            if (err) throw err;
            res.render('view_forms', { forms: results });
        });
    } else {
        res.redirect('/login');
    }
});

// 显示特定表单的提交数据
app.get('/admin/forms/:id/submissions', (req, res) => {
    const formId = req.params.id;

    if (req.session.loggedin) {
        // 获取表单的字段结构
        const queryFormFields = `
            SELECT field_name, field_type
            FROM form_fields
            WHERE template_id = ?
            ORDER BY field_order
        `;

        // 获取提交的数据，并标记所有未读反馈为已读
        const querySubmissions = `
            SELECT id, submission_data, submitted_at, is_read
            FROM form_submissions
            WHERE template_id = ?
            ORDER BY submitted_at DESC
        `;

        // 更新 has_new_submissions 为 FALSE
        const resetTemplateQuery = `
            UPDATE form_templates
            SET has_new_submissions = FALSE
            WHERE id = ?
        `;

        // 更新 form_submissions 表，标记所有未读反馈为已读
        const resetSubmissionsQuery = `
            UPDATE form_submissions
            SET is_read = 1
            WHERE template_id = ?
        `;

        // 首先更新 form_templates 表
        db.query(resetTemplateQuery, [formId], (err, updateResult) => {
            if (err) {
                return res.status(500).send("Error updating form_templates status.");
            }

            // 然后更新 form_submissions 表
            db.query(resetSubmissionsQuery, [formId], (err, updateResult) => {
                if (err) {
                    return res.status(500).send("Error updating form_submissions status.");
                }

                // 获取字段结构和提交的数据
                db.query(queryFormFields, [formId], (err, fieldsResults) => {
                    if (err) throw err;

                    db.query(querySubmissions, [formId], (err, submissionsResults) => {
                        if (err) throw err;

                        // 统计未读反馈数量
                        let unreadCount = 0;
                        submissionsResults.forEach(submission => {
                            if (!submission.is_read) unreadCount++;

                            const date = new Date(submission.submitted_at);
                            submission.formatted_submitted_at = date.getFullYear() + '年' + 
                                                                (date.getMonth() + 1) + '月' + 
                                                                date.getDate() + '日 ' + 
                                                                date.getHours() + ':' + 
                                                                date.getMinutes().toString().padStart(2, '0') + ':' + 
                                                                date.getSeconds().toString().padStart(2, '0');
                        });

                        // 渲染页面，并传递表单字段、提交数据和未读反馈数量
                        res.render('view_submissions', {
                            fields: fieldsResults,
                            submissions: submissionsResults,
                            formId: formId,
                            unreadCount: unreadCount
                        });
                    });
                });
            });
        });
    } else {
        res.redirect('/login');
    }
});

// 标记表单为已查看
app.post('/admin/forms/mark-viewed/:id', (req, res) => {
    const formId = req.params.id;

    const resetQuery = `
        UPDATE form_templates
        SET has_new_submissions = FALSE
        WHERE id = ?
    `;

    db.query(resetQuery, [formId], (err, result) => {
        if (err) {
            return res.status(500).send("Error updating feedback status.");
        }

        res.sendStatus(200); // 返回成功状态
    });
});

// 处理删除数据的请求
app.post('/admin/submissions/:id/delete', (req, res) => {
    const submissionId = req.params.id;

    const deleteQuery = `
        DELETE FROM form_submissions
        WHERE id = ?
    `;

    db.query(deleteQuery, [submissionId], (err, result) => {
        if (err) {
            return res.status(500).send("Error deleting submission.");
        }

        res.sendStatus(200); // 返回成功状态
    });
});

// 处理表单删除请求
app.post('/admin/forms/:id/delete', (req, res) => {
    if (req.session.loggedin) {
        const formId = req.params.id;

        // 删除与表单相关的字段数据
        db.query('DELETE FROM form_fields WHERE template_id = ?', [formId], (err, result) => {
            if (err) throw err;

            // 删除表单模板数据
            db.query('DELETE FROM form_templates WHERE id = ?', [formId], (err, result) => {
                if (err) throw err;

                res.redirect('/admin/forms');
            });
        });
    } else {
        res.redirect('/login');
    }
});

//表单复制
app.post('/admin/forms/:id/copy', (req, res) => {
    const formId = req.params.id;
    const newFormName = req.body.newFormName;

    // 查询原表单模板和字段
    db.query('SELECT * FROM form_templates WHERE id = ?', [formId], (err, formResults) => {
        if (err) {
            return res.status(500).json({ success: false, message: '查询表单模板失败。' });
        }

        if (formResults.length === 0) {
            return res.status(404).json({ success: false, message: '表单未找到。' });
        }

        const originalForm = formResults[0];

        // 插入新的表单模板
        db.query('INSERT INTO form_templates (name, status) VALUES (?, "draft")', [newFormName], (err, insertResult) => {
            if (err) {
                return res.status(500).json({ success: false, message: '复制表单模板失败。' });
            }

            const newFormId = insertResult.insertId;

            // 查询原表单字段
            db.query('SELECT * FROM form_fields WHERE template_id = ?', [formId], (err, fieldResults) => {
                if (err) {
                    return res.status(500).json({ success: false, message: '查询表单字段失败。' });
                }

                const fieldPromises = fieldResults.map(field => {
                    return new Promise((resolve, reject) => {
                        db.query(
                            'INSERT INTO form_fields (template_id, field_name, field_type, options, field_order) VALUES (?, ?, ?, ?, ?)',
                            [newFormId, field.field_name, field.field_type, field.options, field.field_order],
                            (err, result) => {
                                if (err) return reject(err);
                                resolve(result);
                            }
                        );
                    });
                });

                // 插入所有字段后返回成功响应
                Promise.all(fieldPromises)
                    .then(() => res.json({ success: true }))
                    .catch(err => res.status(500).json({ success: false, message: '复制表单字段失败。' }));
            });
        });
    });
});

// 导出数据到Excel
app.get('/admin/submissions/export', (req, res) => {
    const formId = req.query.formId;

    db.query(`
        SELECT submission_data
        FROM form_submissions
        WHERE template_id = ?
        ORDER BY submitted_at DESC
    `, [formId], (err, results) => {
        if (err) throw err;

        const wb = new xl.Workbook();
        const ws = wb.addWorksheet('Submissions');

        if (results.length > 0) {
            // 获取字段名 (表头)
            const firstSubmissionData = JSON.parse(results[0].submission_data);

            // 过滤掉以 "subSelect-" 和 "mainSelect-" 开头的列
            const headers = Object.keys(firstSubmissionData).filter(header => {
                return !header.startsWith('subSelect-') && !header.startsWith('mainSelect-');
            });

            // 添加表头
            headers.forEach((header, index) => {
                ws.cell(1, index + 1).string(header);
            });

            // 添加数据行
            results.forEach((row, rowIndex) => {
                const data = JSON.parse(row.submission_data);

                headers.forEach((header, colIndex) => {
                    // 如果是其他字段，直接显示数据
                    let fieldValue = data[header] || '';

                    // 合并一级和二级菜单（如果需要），但不要输出subSelect
                    const mainSelectField = `mainSelect-${header}`;
                    const subSelectField = `subSelect-${header}`;

                    if (data[mainSelectField]) {
                        fieldValue = `一级: ${data[mainSelectField]}, 二级: ${data[subSelectField] || '无'}`;
                    }

                    ws.cell(rowIndex + 2, colIndex + 1).string(fieldValue);
                });
            });
        } else {
            ws.cell(1, 1).string('无数据');
        }

        // 写入Excel文件并发送
        wb.write('Submissions.xlsx', res);
    });
});

// 前台访问表单页面
app.get('/forms/:id', (req, res) => {
    const formId = req.params.id;
    const submitted = req.query.submitted === 'true'; // 检查是否有提交完成的提示

    // 查询表单模板和字段
    db.query('SELECT * FROM form_templates WHERE id = ?', [formId], (err, formResults) => {
        if (err) throw err;

        if (formResults.length > 0) {
            db.query('SELECT * FROM form_fields WHERE template_id = ?', [formId], (err, fieldResults) => {
                if (err) throw err;

                const form = {
                    id: formResults[0].id,
                    name: formResults[0].name,
                    fields: fieldResults
                };

                // 在渲染时传递 submitted 变量
                res.render('form_display', { form, submitted });
            });
        } else {
            res.send('表单未找到');
        }
    });
});

// 处理前台表单提交（包括文件上传）
app.post('/forms/:id/submit', (req, res) => {
    const form = new formidable.IncomingForm({ encoding: 'utf-8' }); 

    form.parse(req, (err, fields, files) => {
        if (err) {
            console.error('Error parsing the form:', err);
            res.status(500).send('Form parsing error.');
            return;
        }

        console.log('Parsed fields:', fields);
        console.log('Parsed files:', files);

        // 直接使用 `fields`，不进行额外编码处理
        const submissionData = {};
        for (const key in fields) {
            submissionData[key] = fields[key].toString(); // 转为字符串保存
        }

        // 获取当前时间并格式化为 "YYYY年M月D日HH:mm:ss"
        const now = new Date();
        const formattedDate = now.getFullYear() + '年' + 
                              (now.getMonth() + 1) + '月' + 
                              now.getDate() + '日' + 
                              now.getHours() + ':' + 
                              now.getMinutes().toString().padStart(2, '0') + ':' + 
                              now.getSeconds().toString().padStart(2, '0');

        // 将格式化后的日期添加到提交的数据中
        submissionData['提交时间'] = formattedDate;
		
		// 添加一级和二级菜单的字段
        const mainSelectFieldName = `mainSelect-下拉`;
        const subSelectFieldName = `subSelect-下拉`;

        submissionData['一级菜单'] = fields[mainSelectFieldName];  // 存储一级菜单
        submissionData['二级菜单'] = fields[subSelectFieldName];  // 存储二级菜单
		
        console.log('Processed submission data:', submissionData);

        // 将数据保存到数据库
        const formId = req.params.id;
        db.query('INSERT INTO form_submissions (template_id, submission_data) VALUES (?, ?)', [formId, JSON.stringify(submissionData)], (err, result) => {
            if (err) throw err;

            db.query('UPDATE form_templates SET has_new_submissions = TRUE WHERE id = ?', [formId], (err, result) => {
                if (err) throw err;
                res.redirect(`/forms/${formId}?submitted=true`);
            });
        });
    });
});

// 生成二维码并返回HTML和SVG下载链接
app.get('/admin/forms/:id/generate-qr', (req, res) => {
    const formId = req.params.id;
    const format = req.query.format || 'png'; // 默认使用 PNG 格式
    const formUrl = `http://localhost:3000/forms/${formId}`;

    if (format === 'svg') {
        const qrSvg = new QRCodeSVG(formUrl).svg();
        const qrDownloadUrl = `data:image/svg+xml;base64,${Buffer.from(qrSvg).toString('base64')}`;
        res.json({
            qrHtml: `<img src="${qrDownloadUrl}" alt="QR Code" class="mx-auto">`,
            qrDownloadUrl: qrDownloadUrl
        });
    } else {
        QRCode.toDataURL(formUrl, { errorCorrectionLevel: 'H' }, (err, qrCodeUrl) => {
            if (err) {
                console.error("Error generating QR code:", err);
                return res.status(500).send("Error generating QR code.");
            }
            res.json({
                qrHtml: `<img src="${qrCodeUrl}" alt="QR Code" class="mx-auto">`,
                qrDownloadUrl: qrCodeUrl
            });
        });
    }
});

// 处理登出请求
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/admin/forms'); // 如果出错，重定向到表单列表页面
        }
        res.clearCookie('connect.sid'); // 清除浏览器中的会话 cookie 
        res.redirect('/login'); // 重定向到登录页面
    });
});

// 启动服务器
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});