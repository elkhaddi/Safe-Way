from flask import Flask, request, jsonify, make_response,render_template
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from  werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import date, datetime, timedelta
from functools import wraps
from flask_cors import CORS
from flask_migrate import Migrate
from flask_mail import Mail,Message


app = Flask(__name__,template_folder="client/build", static_folder="client/build/static")

app.config['SECRET_KEY'] = 'secret'
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:root@localhost:5432/securityApp"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# mail config

app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '47d08247bc0b4a'
app.config['MAIL_PASSWORD'] = '85c52491c64f59'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)



# Db Models 

class Users(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    firstName = db.Column(db.String())
    lastName = db.Column(db.String())
    birthday = db.Column(db.Date())
    email = db.Column(db.String(70), unique = True)
    passwordHash = db.Column(db.String())

    def __init__(self, firstName, lastName, birthday , email,passwordHash):
        self.firstName = firstName
        self.lastName = lastName
        self.birthday = birthday
        self.email = email
        self.passwordHash = passwordHash

    def __repr__(self):
        return f"<User {self.email}>"


class Declare(db.Model):
    __tablename__ = 'declare'

    id = db.Column(db.Integer, primary_key = True)
    date = db.Column(db.Date())
    description = db.Column(db.String())
    status = db.Column(db.String())
    type = db.Column(db.String())
    localisation_id = db.Column(db.Integer, db.ForeignKey("localisation.id"))
    localisation = db.relationship("Localisation", backref=db.backref("declare", uselist=False))

    def __init__(self,date,description,status,type,localisation):
        self.date  = date
        self.description = description
        self.status = status
        self.type = type
        self.localisation = localisation
    
    def __repr__(self):
        return f"<Declare {self.date}"


class Localisation(db.Model):
    __tablename__ = 'localisation'

    id = db.Column(db.Integer, primary_key = True)
    lng = db.Column(db.Float())
    lat = db.Column(db.Float())

    def __init__(self,lng,lat):
        self.lng  = lng
        self.lat = lat
    
    def __repr__(self):
        return f"<LocLISATION {self.date}"




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
            current_user = Users.query\
                .filter_by(email = data['email']).first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated
  



# Routes 

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """ This is a catch all that is required for react-router """
    return render_template('index.html')






# User Database Route
# this route sends back list of users
@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    # querying the database
    # for all the entries in it
    users = Users.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'firstName' : user.firstName,
            'lastName':user.lastName,
            'email' : user.email
        })
  
    return jsonify({'users': output})
  
# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
  
    user = Users.query\
        .filter_by(email = auth.get('email'))\
        .first()
  
    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
  
    if check_password_hash(user.passwordHash, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'email': user.email,
            'exp' : datetime.utcnow() + timedelta(minutes = 1000000)
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )
  
# signup route
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
  
    # gets name, email and password
    firstName,lastName, email,birthday = data.get('firstName'),data.get('lastName'), data.get('email') , data.get("birthday")
    password = data.get('password')
  
    # checking for existing user
    user = Users.query\
        .filter_by(email = email)\
        .first()
    if not user:
        # database ORM object
        user = Users(
            firstName = firstName,
            lastName = lastName,
            birthday = birthday,
            email = email,
            passwordHash = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


# 
@app.route('/declare',methods=['POST'])
@token_required
def addDeclare(current_user):
    data = request.form
    date,description,status,type = data.get("date"),data.get("description"),data.get("status"),data.get("type")
    lat,lng  = data.get("lat"),data.get("lng")
    if date and description and status and lat and lng and type:
        local = Localisation(lng,lat)
        db.session.add(local)
        declare = Declare(date,description,status,type,localisation=local)
        db.session.add(declare)
        db.session.commit()
        return make_response('Successfully registered.', 201)
    else:
        return make_response('Missing Feilds', 400)


@app.route('/get_declares',methods=['GET'])
@token_required
def getDeclares(current_user):
    try:
        data = Localisation.query.all()
        output = []
        for local in data:
            # appending the user data json
            # to the response list
            output.append({
                'lat' : local.lat,
                'lng':local.lng
            })
        return jsonify({'localisations': output})
    except:
        return make_response('oops sometihng wrong', 400)


@app.route('/contact',methods=['POST'])
def contact():
    data = request.form
    email,nom,prenom,message, = data.get("email"),data.get('nom'),data.get("prenom"),data.get("message")
    msg = Message("new Contact Message",
                  sender=email,
                  recipients=["contact@maroute.ma"])
                  
    msg.body = f"{nom+' ' + prenom} \n message :  {message}"
    mail.send(msg)
    return make_response("mail is sent",200)



    

if __name__ == "__main__":
    app.run()