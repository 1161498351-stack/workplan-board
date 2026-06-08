const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3456;
const JWT_SECRET = process.env.JWT_SECRET || 'workplan-secret-key-change-in-production';

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    req.username = decoded.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

function adminOnly(req, res, next) {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账号和密码' });
  }
  const user = db.findUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '账号或密码错误' });
  }
  const token = jwt.sign({ userId: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role }
  });
});

app.post('/api/auth/register', authMiddleware, adminOnly, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账号和密码' });
  }
  if (username.length < 2) return res.status(400).json({ error: '账号至少2个字符' });
  if (password.length < 4) return res.status(400).json({ error: '密码至少4位' });
  if (db.findUserByUsername(username)) {
    return res.status(400).json({ error: '该账号已存在' });
  }
  const user = db.createUser(username, password, role || 'user');
  if (department) db.updateUserDepartment(user.id, department);
  res.json(user);
});

// Batch create users with random passwords
app.post('/api/users/batch', authMiddleware, adminOnly, (req, res) => {
  const { usernames, department } = req.body;
  if (!usernames || !Array.isArray(usernames) || usernames.length === 0) {
    return res.status(400).json({ error: '请提供用户名列表' });
  }
  // Validate usernames
  const errors = [];
  const created = [];
  for (const raw of usernames) {
    const username = String(raw).trim();
    if (!username || username.length < 2) { errors.push(`${raw}: 账号至少2字符`); continue; }
    if (db.findUserByUsername(username)) { errors.push(`${username}: 已存在`); continue; }
    // Generate complex password: Wp+year+4random
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789@#';
    let rand = '';
    for (let i = 0; i < 6; i++) rand += chars[Math.floor(Math.random() * chars.length)];
    const password = 'Wp@' + new Date().getFullYear() + rand;
    const user = db.createUser(username, password, 'user');
    if (department) db.updateUserDepartment(user.id, department);
    created.push({ username, password });
  }
  res.json({ created, errors });
});

// List all users (for assignee dropdown — any logged-in user can call)
app.get('/api/users/assignable', authMiddleware, (req, res) => {
  const users = db.listUsers();
  res.json(users.map(u => ({ username: u.username, department: u.department })));
});

app.put('/api/auth/password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: '请输入新旧密码' });
  }
  if (newPassword.length < 4) return res.status(400).json({ error: '密码至少4位' });
  const user = db.findUserByUsername(req.username);
  if (!bcrypt.compareSync(oldPassword, user.password_hash)) {
    return res.status(400).json({ error: '当前密码错误' });
  }
  db.changePassword(req.userId, newPassword);
  res.json({ success: true });
});

// Update own department
app.put('/api/auth/department', authMiddleware, (req, res) => {
  const { department } = req.body;
  db.updateUserDepartment(req.userId, department || '');
  res.json({ success: true, department: department || '' });
});

// ============================================================
// USER ROUTES (admin)
// ============================================================
app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  res.json(db.listUsers());
});

app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
  if (parseInt(req.params.id) === req.userId) {
    return res.status(400).json({ error: '不能删除自己' });
  }
  const result = db.deleteUser(parseInt(req.params.id));
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

// ============================================================
// DATA ROUTES (all require auth)
// ============================================================
// Get all data for current user
app.get('/api/data', authMiddleware, (req, res) => {
  const data = db.getCategories(req.userId);
  res.json(data);
});

// Import / replace all data
app.post('/api/data/import', authMiddleware, (req, res) => {
  const { categories } = req.body;
  if (!Array.isArray(categories)) {
    return res.status(400).json({ error: '数据格式错误' });
  }
  db.importData(req.userId, categories);
  res.json({ success: true });
});

// ============================================================
// CATEGORY ROUTES
// ============================================================
app.post('/api/categories', authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: '请输入分组名称' });
  }
  const cat = db.createCategory(req.userId, name.trim());
  res.json(cat);
});

app.put('/api/categories/:id', authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: '请输入分组名称' });
  }
  db.updateCategory(parseInt(req.params.id), req.userId, name.trim());
  res.json({ success: true });
});

app.delete('/api/categories/:id', authMiddleware, (req, res) => {
  db.deleteCategory(parseInt(req.params.id), req.userId);
  res.json({ success: true });
});

// ============================================================
// NOTIFICATION ROUTES
// ============================================================
app.get('/api/notifications', authMiddleware, (req, res) => {
  const notifications = db.getNotifications(req.username);
  const unread = db.getUnreadCount(req.username);
  res.json({ notifications, unreadCount: unread });
});

app.post('/api/notifications/read', authMiddleware, (req, res) => {
  db.markNotificationsRead(req.username);
  res.json({ success: true });
});

// ============================================================
// TASK ROUTES
// ============================================================
app.post('/api/tasks', authMiddleware, (req, res) => {
  const { categoryId, ...data } = req.body;
  if (!categoryId) {
    return res.status(400).json({ error: '请指定所属分组' });
  }
  const task = db.createTask(req.userId, parseInt(categoryId), data);
  res.json(task);
});

app.put('/api/tasks/:id', authMiddleware, (req, res) => {
  const taskId = parseInt(req.params.id);
  // Check if assignee changed — create notification
  if (req.body.assignee !== undefined) {
    const oldAssignee = db.getTaskAssignee(taskId);
    const newAssignee = req.body.assignee;
    if (newAssignee && newAssignee !== oldAssignee && newAssignee !== req.username) {
      const taskName = req.body.name || '任务';
      db.createNotification(newAssignee, req.username, `将事项「${taskName}」分配给了你`, taskName);
    }
  }
  db.updateTask(taskId, req.userId, req.body);
  res.json({ success: true });
});

app.delete('/api/tasks/:id', authMiddleware, (req, res) => {
  db.deleteTask(parseInt(req.params.id), req.userId);
  res.json({ success: true });
});

// ============================================================
// START
// ============================================================
app.listen(PORT, () => {
  console.log(`[Server] 工作计划后端已启动: http://localhost:${PORT}`);
  console.log(`[Server] 默认管理员: admin / admin123`);
});
