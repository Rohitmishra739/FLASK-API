from flask import Flask,jsonify
from flask import request
from flask_sqlalchemy import SQLAlchemy

from flask import request, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps



app=Flask(__name__)


app.config['SECRET_KEY'] = 'qwertyuiop'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/bank_data'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)




'''DATABASE ORM'''
class bank(db.Model):



    
    bank_name = db.Column(db.String(80))
    bank_address= db.Column(db.String(120))
    ifsc=db.Column('ifsc',db.String(),primary_key=True,unique=True)
    bank_branch = db.Column(db.String(70))
    city=db.Column(db.String())
    user_id = db.Column(db.Integer)

    def __init__(self, bank_name, bank_address,ifsc,city,bank_branch,user_id):

        self.bank_name = bank_name
        self.bank_address = bank_address
        self.city=city
        self.ifsc=ifsc
        self.bank_branch=bank_branch
        self.user_id=user_id
    def __repr__(self):
        return f"<item {self.ifsc}>"

    @property
    def serialize(self):
        """
        Return item in serializeable format
        """
        return {"bank_name": self.bank_name, "bank_address": self.bank_address,
                "ifsc":self.ifsc,'bank_branch':self.bank_branch,'city':self.city}    






# ************************************
# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
       
        return  f(current_user, *args, **kwargs)
  
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


#************************************* 


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=5)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})




# -------------------------------------------------------------------------

'''POST api to add the raw data in the database'''


@app.route('/details', methods=['POST'])
def add_details():
  body = request.get_json()
  db.session.add(bank(body['bank_name'],body['bank_address'],body['ifsc'],body['bank_branch'],body['city']))
  db.session.commit()
  return "details added successfully"


'''1.GET  api to fetch bank details given ifsc code'''


@app.route("/details/<bank_ifsc>", methods=["GET"])
@token_required
def details(current_user,bank_ifsc):
    if request.method == "GET":
        try:
            item = bank.query.filter_by(ifsc=bank_ifsc,user_id=current_user.id).first_or_404()

            if not item:
                return jsonify({'message' : 'No todo found!'})
            return jsonify(item.serialize)
        except:
            return jsonify({"error": f"Item {bank_ifsc} not found"})
    else:
        return {"message": "Request method not implemented"}





@app.route("/<bank_name>/<city>", methods=["GET"])
@token_required
def handle_item(current_user,bank_name,city):
    if request.method == "GET":
        try:
            
            item = bank.query.filter_by(bank_name=bank_name,city=city,user_id=current_user.id).first()
            if not item:
                return jsonify({'message' : 'No todo found!'})
            return jsonify(item.serialize)
        except:
            return jsonify({"error": f"Item {bank_name,city} not found"})
    else:
        return {"message": "Request method not implemented"}






if __name__=="__main__":
    app.run(debug=True)




