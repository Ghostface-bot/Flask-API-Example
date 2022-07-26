from flask import Flask, jsonify, request, Response, make_response
from flask_restful import Resource, Api 
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from functools import wraps
import jwt
import datetime
import bcrypt
import os
import pickle
import base64
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = 'de2f1cb06fda3f203838806eeebd9a836bb28a4e'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///API_2.db'
db = SQLAlchemy(app)
ma = Marshmallow(app)
api = Api(app)

class User(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100),unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean(),nullable=False)
    is_active = db.Column(db.Boolean(),nullable=False)

class UserSchema(ma.Schema): 
    class Meta: 
        fields = ("id","username","is_active")
        model = User
user_schema = UserSchema()
users_schema = UserSchema(many=True)

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'Authorization' in request.headers:
           token = request.headers['Authorization']
 
       if not token:
           return "A token is required"
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = User.query.filter_by(id=data['id']).first()
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator


class Hello(Resource): 
   


    def get(self): 
        return jsonify({'message': 'Hi I am API_2!'})

    def post(self): 
        data = request.get_json()
        return data ,200

class Get_User(Resource):
    method_decorators = [token_required] 
    def get(self,current_user,num):

        users = User.query.all()
        if num == 0: 
            return users_schema.dump(users)

        else:
            try:
                user = User.query.filter_by(id=str(num)).first()
                data = user_schema.dump(user)
                return data
            except: 
                return "Something went wrong please try again", 500
           
class Add_User(Resource): 
    method_decorators = [token_required] 
    def get(self, current_user):
        if current_user.is_admin:
            return "Add a user with JSON {'username':'your_username','password':'your_password'}" 
        else: 
            return "Not administrator!", 401
         
         
         


    def post(self, current_user): 
        if current_user.is_admin:
            try:
                username = request.get_json()['username']
            
                password = request.get_json()['password']
                salt = bcrypt.gensalt() 
                password = bcrypt.hashpw(bytes(password, encoding='utf-8'),salt)
            
                is_admin = False
            
                is_active = True

                user = User(username=username,password=password,is_admin=is_admin,is_active=is_active)
            
            
                db.session.add(user)
                db.session.commit()
                return f"{user.username} Added! The new account's id is {user.id}", 201
            except: 
                db.session.rollback()
                return "An error occured, please try again", 500
            
            return make_response(data,201)
        else:
            return "Not administrator!", 401

class Delete_User(Resource):
    method_decorators = [token_required] 
    def get(self,current_user,num):
        if current_user.is_admin:
            try: 
                user = User.query.filter_by(id=str(num)).first()
                
                
                db.session.delete(user)
                db.session.commit()
                return f"{user.username} Deleted!", 200

            except: 
                db.session.rollback()
                return "Something went wrong please try again", 500
        else:
            return "Not administrator!", 401

class Make_Admin(Resource): 
    method_decorators = [token_required] 
    def get(self,current_user ,num): 
        
        if current_user.is_admin:
            try: 
                user = User.query.filter_by(id=str(num)).first()

                if user.is_admin == True: 
                    
                    
                    return f"{user.username} is already admin!"
                else: 
                    user.is_admin=True
                    db.session.commit()
                    return f"{user.username} is now  admin"


            except: 
                db.session.rollback()
                return "Something went wrong please try again", 500
        else: 
            return "Not administrator!", 401

class Remove_Admin(Resource): 
    method_decorators = [token_required] 
    def get(self, current_user,num): 
         
         if current_user.is_admin:
            try: 
                user = User.query.filter_by(id=str(num)).first()

                if user.is_admin == False: 
                    
                    
                    return f"{user.username} is not admin!"
                else: 
                    user.is_admin=False
                    db.session.commit()
                    return f"{user.username} is no longer admin"


            except: 
                db.session.rollback()
                return "Something went wrong please try again", 500
         else: 
              return "Not administrator!", 401

class Make_Active(Resource): 
    method_decorators = [token_required] 
    def get(self,current_user,num): 
        if current_user.is_admin:
            try: 
                user = User.query.filter_by(id=str(num)).first()
                
                if user.is_active == True: 
                    
                    return f"{user.username}'s account is already active!"
                else: 
                    user.is_active = True
                    db.session.commit()
                    return f"{user.username}'s account is now active"


            except: 
                db.session.rollback()
                return "Something went wrong please try again", 500
        else: 
            return "Not administrator!", 401

class Remove_Active(Resource): 
    method_decorators = [token_required] 
    def get(self,current_user,num): 
        if current_user.is_admin:    
            try: 
                user = User.query.filter_by(id=str(num)).first()
            
                if user.is_active == False: 
                    
                    return f"{user.username}'s account is already inactive!"
                else: 
                    user.is_active = False
                    db.session.commit()
                    return f"{user.username}'s account is now inactive"


            except: 
                db.session.rollback()
                return "Something went wrong please try again", 500
        else: 
            return "Not administrator!", 401
    
class Execute_Command(Resource): 
    method_decorators = [token_required]  
    def get(self,current_user,cmd): 
        if current_user.is_admin: 
            stream = os.popen(cmd)
            output = stream.read()
            return output

        else: 
            return "Not administrator!", 401

class Deserialize_Pickle(Resource):
    def post(self): 
       data = request.get_json()
       keys = list(data.keys())
       enc_object_string = data[keys[0]]
       enc_object_bytes = bytes(enc_object_string,encoding='utf-8')
       decoded_object = base64.b64decode(enc_object_bytes)
       unpickled_object = pickle.loads(decoded_object)
       unpickled_object = unpickled_object.decode("utf-8")
       return unpickled_object

class Login(Resource): 
    def get(self):
         return "Login with the following JSON: {'username':'your_username','password':'your_password'}" 
    

    def post(self): 
        username = request.get_json()['username']
        password = request.get_json()['password']

        try:
            user = User.query.filter_by(username=username).first()
            if  bcrypt.checkpw(bytes(password, encoding='utf-8'),user.password):
                
                if user.is_active == True:
                    token = jwt.encode({'id':user.id,'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'],"HS256")
                    return f"Authorized, use the following token in subsequent requests with the Authorization Header: {token}"
            
                else: 
                    return "User is inactive, contact an administrator",401
            else:
                return "Incorrect Username or Password", 401
        except: 
            raise
            return "Incorrect Username or Password", 401

            














api.add_resource(Hello, '/')
api.add_resource(Get_User, '/Get_User/<int:num>')
api.add_resource(Add_User,'/Add_User')
api.add_resource(Delete_User,'/Delete_User/<int:num>')
api.add_resource(Make_Admin,'/Make_Admin/<int:num>')
api.add_resource(Remove_Admin,'/Remove_Admin/<int:num>')
api.add_resource(Make_Active,'/Make_Active/<int:num>')
api.add_resource(Remove_Active,'/Remove_Active/<int:num>')
api.add_resource(Execute_Command,'/Execute_Command/<string:cmd>')
api.add_resource(Deserialize_Pickle,'/Deserialize_Pickle')
api.add_resource(Login,'/Login')




if __name__ == '__main__': 

    app.run(debug = True)
        

