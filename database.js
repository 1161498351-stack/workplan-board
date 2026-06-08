const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'workplan.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ============================================================
// SCHEMA
// ============================================================
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    department TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'P2',
    status TEXT NOT NULL DEFAULT 'not-started',
    assignee TEXT,
    deadline TEXT,
    completed_at TEXT,
    thought TEXT,
    result TEXT,
    contact_person TEXT,
    contact_dept TEXT,
    contact_org TEXT,
    participants TEXT,
    scope TEXT NOT NULL DEFAULT '组织',
    parent_id INTEGER,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_username TEXT NOT NULL,
    from_username TEXT NOT NULL,
    message TEXT NOT NULL,
    task_name TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id);
  CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);
  CREATE INDEX IF NOT EXISTS idx_tasks_category ON tasks(category_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(recipient_username);
`);

// Migrate: add department column if not exists (for existing DB)
try {
  db.exec("ALTER TABLE users ADD COLUMN department TEXT NOT NULL DEFAULT ''");
  console.log('[DB] 已添加 department 列');
} catch(e) { /* already exists */ }
try { db.exec("ALTER TABLE tasks ADD COLUMN contact_person TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE tasks ADD COLUMN contact_dept TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE tasks ADD COLUMN contact_org TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE tasks ADD COLUMN participants TEXT"); } catch(e) {}
try { db.exec("ALTER TABLE tasks ADD COLUMN scope TEXT NOT NULL DEFAULT '组织'"); } catch(e) {}
try { db.exec("ALTER TABLE tasks ADD COLUMN parent_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE"); } catch(e) {}

// ============================================================
// INIT: Create default admin if no users exist
// ============================================================
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run('admin', hash, 'admin');
  console.log('[DB] 已创建默认管理员: admin / admin123');
}

// ============================================================
// USERS
// ============================================================
function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function createUser(username, password, role) {
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username, hash, role);
  return { id: result.lastInsertRowid, username, role };
}

function listUsers() {
  return db.prepare('SELECT id, username, role, department, created_at FROM users ORDER BY id').all();
}

function updateUserDepartment(userId, department) {
  db.prepare('UPDATE users SET department = ? WHERE id = ?').run(department, userId);
}

function deleteUser(id) {
  // Don't delete the last admin
  const admins = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (user && user.role === 'admin' && admins.count <= 1) {
    return { error: '不能删除最后一位管理员' };
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  return { success: true };
}

function changePassword(userId, newPassword) {
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
}

// ============================================================
// CATEGORIES
// ============================================================
function getCategories(userId) {
  const user = db.prepare('SELECT username, department FROM users WHERE id = ?').get(userId);
  const username = user.username;
  const dept = user.department;

  const cats = db.prepare('SELECT * FROM categories WHERE user_id = ? ORDER BY sort_order, id').all(userId);
  const result = cats.map(cat => {
    const tasks = db.prepare('SELECT * FROM tasks WHERE category_id = ? AND parent_id IS NULL ORDER BY sort_order, id').all(cat.id);
    return {
      id: String(cat.id),
      name: cat.name,
      items: tasks.map(t => makeTaskItem(t, cat.id))
    };

    function makeTaskItem(t, catId) {
      const item = ({
        id: String(t.id),
        name: t.name,
        priority: t.priority,
        status: t.status,
        assignee: t.assignee,
        deadline: t.deadline,
        completedAt: t.completed_at,
        thought: t.thought,
        result: t.result,
        contactPerson: t.contact_person,
        contactDept: t.contact_dept,
        contactOrg: t.contact_org, participants: t.participants, scope: t.scope, parentId: t.parent_id ? String(t.parent_id) : null
      });
      const subs = db.prepare('SELECT * FROM tasks WHERE parent_id = ? ORDER BY sort_order, id').all(t.id);
      if (subs.length > 0) item.children = subs.map(s => makeTaskItem(s, catId));
      return item;
    }
  });

  // Add "assigned to me" tasks from same department (different user)
  if (dept) {
    const assignedTasks = db.prepare(`
      SELECT t.*, u.username as owner_name FROM tasks t
      JOIN users u ON t.user_id = u.id
      WHERE t.assignee = ? AND t.user_id != ? AND u.department = ?
      ORDER BY t.created_at DESC
    `).all(username, userId, dept);

    if (assignedTasks.length > 0) {
      result.unshift({
        id: '__assigned__',
        name: '📥 分配给我的',
        items: assignedTasks.map(t => ({
          id: String(t.id),
          name: t.name,
          priority: t.priority,
          status: t.status,
          assignee: t.assignee,
          deadline: t.deadline,
          completedAt: t.completed_at,
          thought: t.thought,
          result: t.result,
          contactPerson: t.contact_person,
          contactDept: t.contact_dept,
          contactOrg: t.contact_org, participants: t.participants, scope: t.scope,
          fromUser: t.owner_name, parentId: null
        }))
      });
    }
  }

  // Add "outgoing" — tasks I created and assigned to registered users
  const outgoingTasks = db.prepare(`
    SELECT t.* FROM tasks t
    INNER JOIN users u ON u.username = t.assignee
    WHERE t.user_id = ? AND t.assignee != ?
    ORDER BY t.updated_at DESC
  `).all(userId, username);
  if (outgoingTasks.length > 0) {
    result.unshift({
      id: '__outgoing__',
      name: '📤 我分发的',
      items: outgoingTasks.map(t => ({
        id: String(t.id),
        name: t.name,
        priority: t.priority,
        status: t.status,
        assignee: t.assignee,
        deadline: t.deadline,
        completedAt: t.completed_at,
        thought: t.thought,
        result: t.result,
        contactPerson: t.contact_person,
        contactDept: t.contact_dept,
        contactOrg: t.contact_org, participants: t.participants, scope: t.scope,
        fromUser: null,
        outgoingTo: t.assignee
      }))
    });
  }

  return result;
}

function createCategory(userId, name) {
  const result = db.prepare('INSERT INTO categories (user_id, name) VALUES (?, ?)').run(userId, name);
  return { id: String(result.lastInsertRowid), name, items: [] };
}

function updateCategory(catId, userId, name) {
  db.prepare('UPDATE categories SET name = ? WHERE id = ? AND user_id = ?').run(name, catId, userId);
}

function deleteCategory(catId, userId) {
  db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run(catId, userId);
}

// ============================================================
// TASKS
// ============================================================
function createTask(userId, categoryId, data) {
  const result = db.prepare(`
    INSERT INTO tasks (category_id, user_id, name, priority, status, assignee, deadline, completed_at, thought, result, contact_person, contact_dept, contact_org, participants, scope, parent_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(categoryId, userId,
    data.name || '新事项',
    data.priority || 'P2',
    data.status || 'not-started',
    data.assignee || null,
    data.deadline || null,
    data.completedAt || null,
    data.thought || null,
    data.result || null,
    data.contactPerson || null,
    data.contactDept || null,
    data.contactOrg || null,
    data.participants || null,
    data.scope || '组织',
    data.parentId || null
  );
  return { id: String(result.lastInsertRowid), ...data, name: data.name || '新事项' };
}

function updateTask(taskId, userId, data) {
  const fields = [];
  const values = [];

  if (data.name !== undefined)       { fields.push('name = ?'); values.push(data.name); }
  if (data.priority !== undefined)   { fields.push('priority = ?'); values.push(data.priority); }
  if (data.status !== undefined)     { fields.push('status = ?'); values.push(data.status); }
  if (data.assignee !== undefined)   { fields.push('assignee = ?'); values.push(data.assignee); }
  if (data.deadline !== undefined)   { fields.push('deadline = ?'); values.push(data.deadline); }
  if (data.completedAt !== undefined){ fields.push('completed_at = ?'); values.push(data.completedAt); }
  if (data.thought !== undefined)    { fields.push('thought = ?'); values.push(data.thought); }
  if (data.result !== undefined)     { fields.push('result = ?'); values.push(data.result); }
  if (data.contactPerson !== undefined) { fields.push('contact_person = ?'); values.push(data.contactPerson); }
  if (data.contactDept !== undefined)   { fields.push('contact_dept = ?'); values.push(data.contactDept); }
  if (data.contactOrg !== undefined)    { fields.push('contact_org = ?'); values.push(data.contactOrg); }
  if (data.participants !== undefined)  { fields.push('participants = ?'); values.push(data.participants); }
  if (data.scope !== undefined)         { fields.push('scope = ?'); values.push(data.scope); }
  if (data.categoryId !== undefined)    { fields.push('category_id = ?'); values.push(data.categoryId); }
  if (data.parentId !== undefined)      { fields.push('parent_id = ?'); values.push(data.parentId); }

  if (fields.length === 0) return;

  fields.push('updated_at = datetime(\'now\',\'localtime\')');
  values.push(taskId, userId);

  db.prepare(`UPDATE tasks SET ${fields.join(', ')} WHERE id = ? AND user_id = ?`).run(...values);
}

function deleteTask(taskId, userId) {
  db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(taskId, userId);
}

// ============================================================
// IMPORT (replace all data for a user)
// ============================================================
function importData(userId, categories) {
  const transaction = db.transaction(() => {
    // Delete all existing data for user
    db.prepare('DELETE FROM tasks WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM categories WHERE user_id = ?').run(userId);

    // Insert new data
    for (const cat of categories) {
      const result = db.prepare('INSERT INTO categories (user_id, name) VALUES (?, ?)').run(userId, cat.name);
      const catId = result.lastInsertRowid;
      if (cat.items) {
        for (const item of cat.items) {
          db.prepare(`
            INSERT INTO tasks (category_id, user_id, name, priority, status, assignee, deadline, completed_at, thought, result, contact_person, contact_dept, contact_org, participants, scope, parent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(catId, userId,
            item.name, item.priority || 'P2', item.status || 'not-started',
            item.assignee || null, item.deadline || null, item.completedAt || null,
            item.thought || null, item.result || null,
            item.contactPerson || null, item.contactDept || null, item.contactOrg || null,
            item.participants || null,
            item.scope || '组织',
            item.parentId || null
          );
        }
      }
    }
  });
  transaction();
}

// ============================================================
// NOTIFICATIONS
// ============================================================
function getNotifications(username) {
  return db.prepare('SELECT * FROM notifications WHERE recipient_username = ? ORDER BY created_at DESC LIMIT 50').all(username);
}

function getUnreadCount(username) {
  const row = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE recipient_username = ? AND is_read = 0').get(username);
  return row.count;
}

function createNotification(recipient, fromUser, message, taskName) {
  db.prepare('INSERT INTO notifications (recipient_username, from_username, message, task_name) VALUES (?, ?, ?, ?)').run(recipient, fromUser, message, taskName);
}

function markNotificationsRead(username) {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE recipient_username = ?').run(username);
}

function getTaskAssignee(taskId) {
  const row = db.prepare('SELECT assignee FROM tasks WHERE id = ?').get(taskId);
  return row ? row.assignee : null;
}

// ============================================================
// EXPORT
// ============================================================

module.exports = {
  findUserByUsername,
  createUser,
  listUsers,
  deleteUser,
  changePassword,
  updateUserDepartment,
  getCategories,
  createCategory,
  updateCategory,
  deleteCategory,
  createTask,
  updateTask,
  deleteTask,
  importData,
  getNotifications,
  getUnreadCount,
  createNotification,
  markNotificationsRead,
  getTaskAssignee
};
