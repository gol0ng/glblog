# app.py

import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect, session, g, abort
import os
import markdown
from werkzeug.security import generate_password_hash, check_password_hash

# --- App 配置 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-change-it'  # 生产环境请使用强密钥
app.config['DATABASE'] = 'blog.db'


# --- 数据库辅助函数 ---

def init_db():
    """初始化数据库，创建所有表结构"""
    db = sqlite3.connect(
        app.config['DATABASE'],
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    db.row_factory = sqlite3.Row

    with db:
        # 创建 users 表
        db.execute("""
                   CREATE TABLE IF NOT EXISTS users
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       UNIQUE
                       NOT
                       NULL,
                       password
                       TEXT
                       NOT
                       NULL,
                       is_admin
                       BOOLEAN
                       NOT
                       NULL
                       DEFAULT
                       0
                   );
                   """)

        # 创建 posts 表
        db.execute("""
                   CREATE TABLE IF NOT EXISTS posts
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       author_id
                       INTEGER
                       NOT
                       NULL,
                       created_date
                       TIMESTAMP
                       NOT
                       NULL
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       title
                       TEXT
                       NOT
                       NULL,
                       content
                       TEXT
                       NOT
                       NULL,
                       FOREIGN
                       KEY
                   (
                       author_id
                   ) REFERENCES users
                   (
                       id
                   )
                       );
                   """)

        # 创建 tags 表
        db.execute("""
                   CREATE TABLE IF NOT EXISTS tags
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       name
                       TEXT
                       UNIQUE
                       NOT
                       NULL
                   );
                   """)

        # 创建 post_tags 关联表
        db.execute("""
                   CREATE TABLE IF NOT EXISTS post_tags
                   (
                       post_id
                       INTEGER
                       NOT
                       NULL,
                       tag_id
                       INTEGER
                       NOT
                       NULL,
                       FOREIGN
                       KEY
                   (
                       post_id
                   ) REFERENCES posts
                   (
                       id
                   ) ON DELETE CASCADE,
                       FOREIGN KEY
                   (
                       tag_id
                   ) REFERENCES tags
                   (
                       id
                   )
                     ON DELETE CASCADE,
                       PRIMARY KEY
                   (
                       post_id,
                       tag_id
                   )
                       );
                   """)

    # 确保外键约束启用
    db.execute("PRAGMA foreign_keys = ON")
    db.close()


def get_db():
    """获取数据库连接，确保表已存在"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        init_db()  # 使用IF NOT EXISTS语法，可以安全重复执行
        # 启用外键约束
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    """在请求结束后关闭数据库连接"""
    db = g.pop('db', None)
    if db is not None:
        db.close()


# 应用启动时确保数据库和表存在
with app.app_context():
    init_db()


# --- 辅助函数 ---
def is_admin():
    """检查当前用户是否是管理员"""
    return session.get('is_admin', False)


def get_current_user_id():
    """获取当前登录用户的ID"""
    return session.get('user_id')


# --- 路由和其它函数 ---

@app.route('/')
def index():
    db = get_db()
    try:
        posts_query = """
                      SELECT p.id, \
                             p.title, \
                             u.username                 as author, \
                             p.created_date,
                             GROUP_CONCAT(t.name, ', ') as tags
                      FROM posts p
                               JOIN users u ON p.author_id = u.id
                               LEFT JOIN post_tags pt ON p.id = pt.post_id
                               LEFT JOIN tags t ON pt.tag_id = t.id
                      GROUP BY p.id
                      ORDER BY p.created_date DESC; \
                      """
        posts = db.execute(posts_query).fetchall()
        return render_template('index.html', posts=posts)
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            init_db()
            return redirect(url_for('index'))
        raise


@app.route('/post/<int:post_id>')
def post(post_id):
    db = get_db()
    post_query = """
                 SELECT p.id, \
                        p.title, \
                        u.username                 as author, \
                        p.created_date, \
                        p.content,
                        GROUP_CONCAT(t.name, ', ') as tags
                 FROM posts p
                          JOIN users u ON p.author_id = u.id
                          LEFT JOIN post_tags pt ON p.id = pt.post_id
                          LEFT JOIN tags t ON pt.tag_id = t.id
                 WHERE p.id = ?
                 GROUP BY p.id; \
                 """
    post = db.execute(post_query, (post_id,)).fetchone()

    if post is None:
        abort(404)

    # 将Markdown内容转换为HTML
    post_content = markdown.markdown(post['content'])
    return render_template('post.html', post=post, post_content=post_content)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        db = get_db()
        error = None

        if not username:
            error = '用户名不能为空'
        elif not password:
            error = '密码不能为空'
        elif len(password) < 6:
            error = '密码长度至少为6个字符'
        elif password != confirm_password:
            error = '两次输入的密码不一致'
        elif db.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = f'用户名 {username} 已被注册'

        if error is None:
            db.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                (username, generate_password_hash(password), 0)
            )
            db.commit()
            flash('注册成功！请登录', 'success')
            return redirect(url_for('login'))

        flash(error, 'error')

    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        error = None
        if user is None:
            error = '用户名错误'
        elif not check_password_hash(user['password'], password):
            error = '密码错误'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session['logged_in'] = True
            flash('登录成功！', 'success')
            return redirect(url_for('index'))

        flash(error, 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('你已成功登出。', 'success')
    return redirect(url_for('index'))


@app.route('/create', methods=('GET', 'POST'))
def create():
    if not session.get('logged_in') or not is_admin():  # 添加管理员权限检查
        abort(403)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        tags_str = request.form['tags']
        if not title or not content:
            flash('标题和内容不能为空！', 'error')
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)',
                (title, content, get_current_user_id())
            )
            post_id = cursor.lastrowid
            process_tags(post_id, tags_str, db)
            db.commit()
            flash('文章已成功创建！', 'success')
            return redirect(url_for('post', post_id=post_id))
    return render_template('edit.html')

@app.route('/edit/<int:post_id>', methods=('GET', 'POST'))
def edit(post_id):
    if not session.get('logged_in') or not is_admin():
        abort(403)
    db = get_db()
    post_query = """
                 SELECT p.id, p.title, p.content, GROUP_CONCAT(t.name, ', ') as tags
                 FROM posts p
                          LEFT JOIN post_tags pt ON p.id = pt.post_id
                          LEFT JOIN tags t ON pt.tag_id = t.id
                 WHERE p.id = ?
                 GROUP BY p.id; \
                 """
    post = db.execute(post_query, (post_id,)).fetchone()
    if post is None:
        abort(404)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        tags_str = request.form['tags']
        if not title or not content:
            flash('标题和内容不能为空！', 'error')
        else:
            db.execute(
                'UPDATE posts SET title = ?, content = ? WHERE id = ?',
                (title, content, post_id)
            )
            db.execute('DELETE FROM post_tags WHERE post_id = ?', (post_id,))
            process_tags(post_id, tags_str, db)
            db.commit()
            flash('文章已成功更新！', 'success')
            return redirect(url_for('post', post_id=post_id))
    return render_template('edit.html', post=post)


@app.route('/delete/<int:post_id>', methods=('POST',))
def delete(post_id):
    if not session.get('logged_in') or not is_admin():
        abort(403)
    db = get_db()
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('文章已成功删除！', 'success')
    return redirect(url_for('index'))


def process_tags(post_id, tags_str, db):
    tag_names = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
    if not tag_names:
        return
    cursor = db.cursor()
    for name in tag_names:
        cursor.execute('SELECT id FROM tags WHERE name = ?', (name,))
        tag = cursor.fetchone()
        if tag:
            tag_id = tag['id']
        else:
            cursor.execute('INSERT INTO tags (name) VALUES (?)', (name,))
            tag_id = cursor.lastrowid
        cursor.execute(
            'INSERT OR IGNORE INTO post_tags (post_id, tag_id) VALUES (?, ?)',
            (post_id, tag_id)
        )


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')