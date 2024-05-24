from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
   return User.query.get(user_id)

@app.route('/login', methods=['POST'])
def login():
   data = request.json
   username = data.get('username')
   password = data.get('password')

   if username and password:
      user = User.query.filter_by(username=username).first()

      if user and bcrypt.checkpw(str.encode(password), user.password):
         login_user(user)
         return jsonify({'message': 'Autenticação realizada com sucesso'})

   return jsonify({'message': 'Credenciais inválidas'}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
   logout_user()
   return jsonify({ 'message': 'Logout realizado com sucesso' })

@app.route('/user', methods=['POST'])
def create_user():
   data = request.json
   username, password = data.get('username'), data.get('password')

   if username and password:
      hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())

      user = User(username=username, password=hashed_password)
      db.session.add(user)
      db.session.commit()

      return jsonify({'message': 'Usuário cadastrado com sucesso'})

   return jsonify({ 'message': 'Dados inválidos' }), 401

@app.route('/user/<int:id_user>', methods=['POST'])
@login_required
def read_user(id_user):
   user = User.query.get(id_user)

   if user:
      return { 'username': user.username }
   
   return jsonify({ 'message': 'Usuário não encontrado' }), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
   data = request.json
   user = User.query.get(id_user)

   if id_user != current_user.id and current_user.role == 'user':
      return jsonify({ 'message': 'Operação não permitida' }), 403
   
   if user and data.get('password'):
      user.password = data.get('password')
      db.session.commit()

      return jsonify({ 'message': 'Usuário atualizado com sucesso' })
   
   return jsonify({ 'message': 'Usuário não encontrado' }), 404

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
   user = User.query.get(id_user)

   if current_user.role != 'admin':
      return jsonify({ 'message': 'Operação não permitida' }), 403
   
   if user and id_user != current_user.id:
      db.session.delete(user)
      db.session.commit()
      return jsonify({ 'message': 'Usuário deletado com sucesso' })
   
   return jsonify({ 'message': 'Usuário não encontrado' }), 404

with app.app_context():
   db.create_all()

if __name__ == '__main__':
   app.run(debug=True)