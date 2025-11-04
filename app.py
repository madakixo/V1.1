# app.py – XO-Connects v6.4 FINAL
import os, uuid, eventlet
eventlet.monkey_patch()
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY='xo-sky-2025',
        SQLALCHEMY_DATABASE_URI='sqlite:///xo.db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        UPLOAD_FOLDER='static/uploads',
        VOICE_FOLDER='static/uploads/voice',
        MAX_CONTENT_LENGTH=50 * 1024 * 1024
    )
    Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
    Path(app.config['VOICE_FOLDER']).mkdir(exist_ok=True)

    db = SQLAlchemy(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

    # MODELS
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        profile_picture = db.Column(db.String(200), default='default.png')
        is_online = db.Column(db.Boolean, default=False)
        is_admin = db.Column(db.Boolean, default=False)
        is_banned = db.Column(db.Boolean, default=False)
        posts = db.relationship('Post', backref='author', lazy=True)

    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        content = db.Column(db.Text, nullable=False)
        media = db.Column(db.String(200))
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    class Message(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        content = db.Column(db.Text)
        voice_note = db.Column(db.String(200))
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    class ModLog(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        target_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        action = db.Column(db.String(20), nullable=False)
        reason = db.Column(db.String(200))
        timestamp = db.Column(db.DateTime, default=datetime.utcnow)
        admin = db.relationship('User', foreign_keys=[admin_id])
        target = db.relationship('User', foreign_keys=[target_id])

    @login_manager.user_loader
    def load_user(uid): return User.query.get(int(uid))

    @app.context_processor
    def inject_user(): return dict(current_user=current_user)

    # ROUTES
    @app.route('/')
    def index(): return redirect(url_for('login'))

    @app.route('/login', methods=['GET','POST'])
    def login():
        if current_user.is_authenticated: return redirect(url_for('home'))
        if request.method == 'POST':
            u = User.query.filter_by(username=request.form['username']).first()
            if u and not u.is_banned and check_password_hash(u.password_hash, request.form['password']):
                login_user(u); u.is_online = True; db.session.commit()
                return redirect(url_for('home'))
            flash('Invalid username or password', 'danger')
        return render_template('auth/login.html')

    @app.route('/register', methods=['GET','POST'])
    def register():
        if current_user.is_authenticated: return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form['username'].strip()
            email = request.form['email'].strip().lower()
            pw = request.form['password']
            if User.query.filter_by(username=username).first():
                flash('Username taken', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('Email taken', 'danger')
            else:
                u = User(username=username, email=email,
                         password_hash=generate_password_hash(pw),
                         is_admin=(User.query.count()==0))
                db.session.add(u); db.session.commit()
                flash('Account created!', 'success')
                return redirect(url_for('login'))
        return render_template('auth/register.html')

    @app.route('/logout')
    @login_required
    def logout():
        current_user.is_online = False
        db.session.commit()
        logout_user()
        return redirect(url_for('login'))

    @app.route('/home', methods=['GET','POST'])
    @login_required
    def home():
        if current_user.is_banned: return redirect(url_for('banned'))
        if request.method == 'POST':
            content = request.form.get('content','').strip()
            post = Post(content=content or 'Posted media', user_id=current_user.id)
            if 'media' in request.files and request.files['media'].filename:
                f = request.files['media']
                ext = f.filename.rsplit('.', 1)[1].lower() if '.' in f.filename else 'jpg'
                name = f"{uuid.uuid4().hex}.{ext}"
                f.save(Path(app.config['UPLOAD_FOLDER'])/name)
                post.media = name
            db.session.add(post); db.session.commit()
        posts = Post.query.order_by(Post.timestamp.desc()).limit(50).all()
        return render_template('home.html', posts=posts)

    @app.route('/messages')
    @login_required
    def messages():
        # FIXED: NO JOIN – 100% SAFE
        contacts = User.query.filter(
            User.id.in_(
                db.session.query(Message.sender_id).filter(Message.recipient_id == current_user.id)
                .union(db.session.query(Message.recipient_id).filter(Message.sender_id == current_user.id))
            ),
            User.id != current_user.id
        ).distinct().all()
        return render_template('messages.html', contacts=contacts)

    @app.route('/chat/<username>')
    @login_required
    def chat(username):
        other = User.query.filter_by(username=username).first_or_404()
        room = f"chat_{min(current_user.id, other.id)}_{max(current_user.id, other.id)}"
        
        msgs = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == other.id)) |
            ((Message.sender_id == other.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp).all()
        
        return render_template('chat.html', other=other, room=room, messages=msgs)

    @app.route('/video/<username>')
    @login_required
    def video_call(username):
        callee = User.query.filter_by(username=username).first_or_404()
        return render_template('video/call.html', callee=callee)

    @app.route('/toggle-theme')
    def toggle_theme():
        session['theme'] = 'sky' if session.get('theme') != 'sky' else 'light'
        return redirect(request.referrer or url_for('home'))

    @app.route('/banned')
    def banned(): return render_template('banned.html')

    # ADMIN
    @app.route('/admin')
    @login_required
    def admin():
        if not current_user.is_admin: abort(403)
        users = User.query.all()
        logs = ModLog.query.order_by(ModLog.timestamp.desc()).limit(50).all()
        return render_template('admin/dashboard.html', users=users, logs=logs)

    def log_mod(action, target, reason=''):
        log = ModLog(admin_id=current_user.id, target_id=target.id, action=action, reason=reason)
        db.session.add(log); db.session.commit()

    @app.route('/admin/ban/<int:uid>', methods=['POST'])
    @login_required
    def ban(uid):
        if not current_user.is_admin: abort(403)
        u = User.query.get_or_404(uid)
        u.is_banned = True
        log_mod('ban', u, request.form.get('reason',''))
        flash(f'@{u.username} banned', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/unban/<int:uid>')
    @login_required
    def unban(uid):
        if not current_user.is_admin: abort(403)
        u = User.query.get_or_404(uid)
        u.is_banned = False
        log_mod('unban', u)
        flash(f'@{u.username} unbanned', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/delete/<int:uid>')
    @login_required
    def delete(uid):
        if not current_user.is_admin: abort(403)
        u = User.query.get_or_404(uid)
        if u.is_admin: flash('Cannot delete admin', 'danger')
        else:
            log_mod('delete', u)
            db.session.delete(u); db.session.commit()
            flash(f'@{u.username} deleted', 'success')
        return redirect(url_for('admin'))

    @app.route('/uploads/<path:filename>')
    def uploads(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    # SOCKET.IO
    @socketio.on('join')
    def on_join(data): join_room(data['room'])

    @socketio.on('send_message')
    def send_msg(data):
        msg = Message(sender_id=current_user.id, recipient_id=data['recipient_id'], content=data['content'])
        db.session.add(msg); db.session.commit()
        emit('receive_message', {
            'sender': current_user.username,
            'content': data['content'],
            'time': msg.timestamp.strftime('%H:%M')
        }, room=data['room'])

    @socketio.on('voice_note')
    def voice_note(data):
        blob = request.files['audio']
        name = f"voice_{uuid.uuid4().hex}.webm"
        blob.save(Path(app.config['VOICE_FOLDER'])/name)
        msg = Message(sender_id=current_user.id, recipient_id=data['recipient_id'], voice_note=name)
        db.session.add(msg); db.session.commit()
        emit('receive_voice', {
            'sender': current_user.username,
            'url': url_for('uploads', filename=f'voice/{name}'),
            'time': msg.timestamp.strftime('%H:%M')
        }, room=data['room'])

    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(username='admin', email='admin@xo.com',
                         password_hash=generate_password_hash('xo123'), is_admin=True)
            db.session.add(admin); db.session.commit()

    return app, socketio

if __name__ == '__main__':
    app, socketio = create_app()
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
