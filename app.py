# from flask import Flask, request, jsonify
# from flask_sqlalchemy import SQLAlchemy
# import os


# app = Flask(__name__)

# if __name__ == '__main__':
#     app.run(debug=True)


# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/bank_data'
# app.debug=True
# db = SQLAlchemy(app)



# class Item(db.Model):
#     # __tablename__='bank'

#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(80), unique=True, nullable=False)
#     content = db.Column(db.String(120), unique=True, nullable=False)

#     def __init__(self, title, content):
#         self.title = title
#         self.content = content



# db.create_all()


# @app.route('/items/<id>', methods=['GET'])
# def get_item(id):
#   item = Item.query.get(id)
#   del item.__dict__['_sa_instance_state']
#   return jsonify(item.__dict__)


# @app.route('/items', methods=['GET'])
# def get_items():
#   items = []
#   for item in db.session.query(Item).all():
#     del item.__dict__['_sa_instance_state']
#     items.append(item.__dict__)
#   return jsonify(items)


# @app.route('/items', methods=['POST'])
# def create_item():
#   body = request.get_json()
#   db.session.add(Item(body['title'], body['content']))
#   db.session.commit()
#   return "item created"


# @app.route('/items/<id>', methods=['PUT'])
# def update_item(id):
#   body = request.get_json()
#   db.session.query(Item).filter_by(id=id).update(
#     dict(title=body['title'], content=body['content']))
#   db.session.commit()
#   return "item updated"



# @app.route('/items/<id>', methods=['DELETE'])
# def delete_item(id):
#   db.session.query(Item).filter_by(id=id).delete()
#   db.session.commit()
#   return "item deleted"



# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
# import jwt
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
if __name__ == '__main__':
    app.run(debug=True,port=8080,use_reloader=False)



app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/bank_data'

db = SQLAlchemy(app)

# # creates Flask object
# app = Flask(__name__)
# # configuration
# # NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# # INSTEAD CREATE A .env FILE AND STORE IN IT
# app.config['SECRET_KEY'] = 'your secret key'
# # database name
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# # creates SQLALCHEMY object
# db = SQLAlchemy(app)

# Using flask to make an api
# import necessary libraries and functions


# on the terminal type: curl http://127.0.0.1:5000/
# returns hello world when we use GET.
# returns the data that we send when we use POST.
@app.route('/', methods = ['GET', 'POST'])
def home():
	if(request.method == 'GET'):

		data = "hello world"
		return jsonify({'data': data})


# A simple function to calculate the square of a number
# the number to be squared is sent in the URL when we use GET
# on the terminal type: curl http://127.0.0.1:5000 / home / 10
# this returns 100 (square of 10)
@app.route('/home/<int:num>', methods = ['GET'])
def disp(num):

	return jsonify({'data': num**2})






# # database orm
# class bank(db.Model):


#   id = db.Column(db.Integer, primary_key=True)
#   bank_name = db.Column(db.String(80),  nullable=False)
#   bank_address= db.Column(db.String(120), nullable=False)
#   bank_ifsc=db.Column(db.String(50))
#   bank_branch = db.Column(db.String(70))

#   def __init__(self, bank_name, bank_address,bank_ifsc,bank_branch):

#     self.bank_name = bank_name
#     self.bank_address = bank_address
#     self.bank_ifsc=bank_ifsc
#     self.bank_branch=bank_branch




# decorator for verifying the JWT
# def token_required(f):
# 	@wraps(f)
# 	def decorated(*args, **kwargs):
# 		token = None
# 		# jwt is passed in the request header
# 		if 'x-access-token' in request.headers:
# 			token = request.headers['x-access-token']
# 		# return 401 if token is not passed
# 		if not token:
# 			return jsonify({'message' : 'Token is missing !!'}), 401

# 		try:
# 			# decoding the payload to fetch the stored details
# 			data = jwt.decode(token, app.config['SECRET_KEY'])
# 			current_user = User.query\
# 				.filter_by(public_id = data['public_id'])\
# 				.first()
# 		except:
# 			return jsonify({
# 				'message' : 'Token is invalid !!'
# 			}), 401
# 		# returns the current logged in users contex to the routes
# 		return f(current_user, *args, **kwargs)

# 	return decorated




# @app.route('/', methods=['POST'])
# def add_details():
#   body = request.get_json()
#   db.session.add(bank(body['bank_name'],body['bank_address'],body['bank_ifsc'],body['bank_branch']))
#   db.session.commit()
#   return "details added successfully"



# User Database Route
# this route sends back list of users 
# @app.route('/user', methods =['GET'])
# @token_required
# def get_all_users(current_user):
# 	# querying the database
# 	# for all the entries in it
# 	users = User.query.all()
# 	# converting the query objects
# 	# to list of jsons
# 	output = []
# 	for user in users:
# 		# appending the user data json
# 		# to the response list
# 		output.append({
# 			'public_id': user.public_id,
# 			'name' : user.name,
# 			'email' : user.email
# 		})

# 	return jsonify({'users': output})

# # route for logging user in
# @app.route('/login', methods =['POST'])
# def login():
# 	# creates dictionary of form data
# 	auth = request.form

# 	if not auth or not auth.get('email') or not auth.get('password'):
# 		# returns 401 if any email or / and password is missing
# 		return make_response(
# 			'Could not verify',
# 			401,
# 			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
# 		)

# 	user = User.query\
# 		.filter_by(email = auth.get('email'))\
# 		.first()

# 	if not user:
# 		# returns 401 if user does not exist
# 		return make_response(
# 			'Could not verify',
# 			401,
# 			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
# 		)

# 	if check_password_hash(user.password, auth.get('password')):
# 		# generates the JWT Token
# 		token = jwt.encode({
# 			'public_id': user.public_id,
# 			'exp' : datetime.utcnow() + timedelta(minutes = 30)
# 		}, app.config['SECRET_KEY'])

# 		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
# 	# returns 403 if password is wrong
# 	return make_response(
# 		'Could not verify',
# 		403,
# 		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
# 	)

# # signup route
# @app.route('/signup', methods =['POST'])
# def signup():
# 	# creates a dictionary of the form data
# 	data = request.form

# 	# gets name, email and password
# 	name, email = data.get('name'), data.get('email')
# 	password = data.get('password')

# 	# checking for existing user
# 	user = User.query\
# 		.filter_by(email = email)\
# 		.first()
# 	if not user:
# 		# database ORM object
# 		user = User(
# 			public_id = str(uuid.uuid4()),
# 			name = name,
# 			email = email,
# 			password = generate_password_hash(password)
# 		)
# 		# insert user
# 		db.session.add(user)
# 		db.session.commit()

# 		return make_response('Successfully registered.', 201)
# 	else:
# 		# returns 202 if user already exists
# 		return make_response('User already exists. Please Log in.', 202)

# if __name__ == "__main__":
# 	# setting debug to True enables hot reload
# 	# and also provides a debugger shell
# 	# if you hit an error while running the server
# 	app.run(debug = True)



