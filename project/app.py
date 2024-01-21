from flask import Flask, request, jsonify
from .db import db , State , University , User , Subject
import os
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
from flasgger import Swagger
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///university.db'
app.config['SECRET_KEY'] = '0123456789'
app.instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')


db.init_app(app)

with app.app_context():
    db.create_all()


Swagger(app)
bcrypt = Bcrypt()
CORS(app)

# register a user
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    ---
    tags:
      - user
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
            is_admin:
              type: boolean
    responses:
      201:
        description: User registered successfully
      400:
        description: Invalid request or username already taken
    """
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request. Please provide username and password.'}), 400

    username = data['username']
    password = data['password']
    is_admin = data.get('is_admin', False)
    email = data.get('email', '')  # Default value is an empty string
    sector = data.get('sector', '')  # Default value is an empty string
    NEgrade = data.get('NEgrade', 0.0)  # Default value is 0.0

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long.'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Registration failed. Please choose a different username.'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(
         username=username,
         password=hashed_password,
         email=email,
         sector=sector,
         NEgrade=NEgrade,
         is_admin=is_admin
        )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful'}), 201

# Route to update user credentials by username
@app.route('/users/<string:username>', methods=['PUT'])
@login_required
def update_user_credentials(username):
    """
    Update user credentials by username
    ---
    tags:
      - user
    parameters:
      - name: username
        in: path
        type: string
        required: true
        description: The username of the user to be updated.
      - name: data
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            email:
              type: string
            sector:
              type: string
            NEgrade:
              type: number
            password:
              type: string
    responses:
      200:
        description: User credentials updated successfully.
      400:
        description: Invalid request. Please provide data for update.
      404:
        description: User not found.
      422:
        description: Password must be at least 6 characters long.
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Invalid request. Please provide data for update.'}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found.'}), 404

    # Update fields if provided in the request data
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.sector = data.get('sector', user.sector)
    user.NEgrade = data.get('NEgrade', user.NEgrade)

    # Check if a new password is provided and update it
    new_password = data.get('password')
    if new_password:
        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long.'}), 400
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    db.session.commit()

    return jsonify({'message': 'User credentials updated successfully'}), 200


login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#login
@app.route('/login', methods=['POST'])
def login():
    """
    User login endpoint.
    ---
    tags:
      - user
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
      200:
        description: User is already logged in
    """
    if current_user.is_authenticated:
        return jsonify({'message': 'User is already logged in'})

    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

#logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    User logout endpoint.
    ---
    tags:
      - user
    responses:
      200:
        description: Logout successful
      401:
        description: Unauthorized - User not logged in or already logged out
    security:
      - apiKeyAuth: []
    """
    if not current_user.is_authenticated:
        return jsonify({'error': 'Unauthorized - User not logged in or already logged out'}), 401

    logout_user()
    return jsonify({'message': 'Logout successful'}), 200




def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user.is_admin:
            return fn(*args, **kwargs)
        else:
            return jsonify({'error': 'Permission denied. Admin access required.'}), 403
    return wrapper

# Admin-only delete users function
@app.route('/users/<string:username>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(username):
    """
        Delete a user by username 
        ---
        tags:
          - admin_only
        parameters:
          - name: username
            in: path
            type: string
            required: true
            description: The username of the user to be deleted.
        responses:
          200:
            description: User deleted successfully.
          403:
            description: Permission denied. Admin access required.
          404:
            description: User not found.
        """
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found.'}), 404
    
    Subject.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'User {username} deleted successfully'}), 200


# add subjects to user by name
@app.route('/users/<string:username>/subjects', methods=['POST'])
#@login_required
def add_subject(username):
    """
    Add subjects to a user by username.
    ---
    tags:
      - student
    parameters:
      - name: username
        in: path
        type: string
        required: true
      - name: body
        in: body
        schema:
          type: object
          properties:
            math:
              type: number
            science:
              type: number
            physics:
              type: number
            french:
              type: number
            english:
              type: number
            arabic:
              type: number
            philosophy:
              type: number
            computer_science:
              type: number
            hist_geo:
              type: number
            economy:
              type: number
            gestion:
              type: number
            technology:
              type: number
            sport:
              type: number
    responses:
      201:
        description: Subject added successfully
      404:
        description: User not found
      500:
        description: Internal Server Error
    """
    data = request.get_json()

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found.'}), 404

    new_subject = Subject(
        user_id=user.id,
        math=data.get('math', 0.0),
        science=data.get('science', 0.0),
        physics=data.get('physics', 0.0),
        french=data.get('french', 0.0),
        english=data.get('english', 0.0),
        arabic=data.get('arabic', 0.0),
        philosophy=data.get('philosophy', 0.0),
        computer_science=data.get('computer_science', 0.0),
        hist_geo=data.get('hist_geo', 0.0),
        economy=data.get('economy', 0.0),
        gestion=data.get('gestion', 0.0),
        technology=data.get('technology', 0.0),
        sport=data.get('sport', 0.0)
    )

    try:
        user.NEgrade = round(new_subject.calculate_NEgrade(user.sector), 2)
        db.session.add(new_subject)
        db.session.commit()
        return jsonify({'message': 'Subject added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Get NEgrade for a user by username
@app.route('/users/<string:username>/NEgrade', methods=['GET'])
#@login_required
def get_NEgrade(username):
    """
    Get NEgrade for a user by username.
    ---
    tags:
      - student
    parameters:
      - name: username
        in: path
        type: string
        required: true
    responses:
      200:
        description: NEgrade retrieved successfully
        schema:
          type: object
          properties:
            NEgrade:
              type: number
      404:
        description: User not found
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found.'}), 404

    return jsonify({'NEgrade': user.NEgrade}), 200




# Create a state
@app.route('/states', methods=['POST'])
@login_required
@admin_required
def create_state():
    """
    Create a new state.
    ---
    tags:
      - admin_only
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
    responses:
      201:
        description: State added successfully
        schema:
          type: object
          properties:
            message:
              type: string
            id:
              type: integer
    """
    data = request.json
    state_name = data.get('name')
    existing_state = State.query.filter_by(name=state_name).first()
    if existing_state:
        return jsonify({'error': 'State with the same name already exists'}), 400
    data = request.json
    new_state = State(name=data['name'])
    db.session.add(new_state)
    db.session.commit()
    return jsonify({'message': 'State added successfully', 'id': new_state.id}), 201


# Get all states
@app.route('/states', methods=['GET'])
@login_required
def get_all_states():
    """
    Get information about all states and their universities.
    ---
    tags:
      - filters
    responses:
      200:
        description: List of states and their universities
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              university_number:
                type: integer
              universities:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: integer
                    name:
                      type: string
                    status:
                      type: string
                    specialty:
                      type: string
      401:
        description: Unauthorized - Login required
    """
    states = State.query.all()
    states_list = [{'id': state.id,
                    'name': state.name,
                    'university_number': state.university_number,
                    'universities': [{'id': uni.id,
                                      'name': uni.name,
                                      'status': uni.status,
                                      'specialty': uni.specialty} for uni in state.universities]}
                   for state in states]
    return jsonify(states_list)

# Create a university in a specific state
@app.route('/states/<string:state_name>/universities', methods=['POST'])
@login_required
@admin_required
def create_university(state_name):
    """
    Create a new university in a specific state.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            location:
              type: string
            status:
              type: string
            tuition_fee:
              type: number
            specialty:
              type: string
            degree:
              type: string
            student_capacity:
              type: integer
            last_year_score:
              type: number
    responses:
      201:
        description: University created successfully
        schema:
          type: object
          properties:
            message:
              type: string
            id:
              type: integer
      400:
        description: University with the same parameters already exists in the state
    """
    data = request.json
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    # Check if a university with the same parameters already exists in the state
    existing_university = University.query.filter_by(
        name=data['name'],
        description=data.get('description'),
        location=data.get('location'),
        status=data.get('status'),
        tuition_fee=data.get('tuition_fee'),
        specialty=data.get('specialty'),
        degree=data.get('degree'),
        student_capacity=data.get('student_capacity'),
        last_year_score=data.get('last_year_score'),
        state=state
    ).first()

    if existing_university:
        return jsonify({'error': 'University with the same parameters already exists in the state'}), 400

    new_university = University(name=data['name'],
                                 description=data.get('description'),
                                 location=data.get('location'),
                                 status=data.get('status'),
                                 tuition_fee=data.get('tuition_fee'),
                                 specialty=data.get('specialty'),
                                 degree=data.get('degree'),
                                 student_capacity=data.get('student_capacity'),  
                                 last_year_score=data.get('last_year_score'),  
                                 state=state)

    state.universities.append(new_university)
    state.university_number += 1

    db.session.add(new_university)
    db.session.commit()

    return jsonify({'message': 'University created successfully', 'id': new_university.id}), 201

# Get all universities in a given state.
@app.route('/states/<string:state_name>/universities', methods=['GET'])
#@login_required
def get_universities_in_state(state_name):
    """
    Get information about all universities in a specific state.
    ---
    tags:
      - filters
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities in the specified state
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              status:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              specialty:
                type: string
              degree:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'status': uni.status,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'specialty': uni.specialty,
                          'degree': uni.degree,
                          'student_capacity': uni.student_capacity,  
                          'last_year_score': uni.last_year_score}  
                         for uni in state.universities]
    # Get filter parameters from query string
    status_filter = request.args.get('status')
    specialty_filter = request.args.get('specialty')
    degree_filter = request.args.get('degree')

    # Apply filters if provided
    filtered_universities = [uni for uni in universities_list
                            if (not status_filter or uni['status'] == status_filter) and
                                (not specialty_filter or uni['specialty'] == specialty_filter) and
                                (not degree_filter or uni['degree'] == degree_filter)]

    return jsonify(filtered_universities)

    




#delete a state
@app.route('/states/<string:state_name>', methods=['DELETE'])
@login_required
@admin_required
def delete_state(state_name):
    """
    Delete a state and its associated universities.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
    responses:
      200:
        description: State and associated universities deleted successfully
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    # Delete all universities associated with the state
    for university in state.universities:
        db.session.delete(university)

    db.session.delete(state)
    db.session.commit()
    return jsonify({'message': 'State and associated universities deleted successfully'})




# Update a state
@app.route('/states/<string:state_name>', methods=['PUT'])
@login_required
@admin_required
def update_state(state_name):
    """
    Update information about a state.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
    responses:
      200:
        description: State updated successfully
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    data = request.json
    state.name = data.get('name', state.name)

    db.session.commit()
    return jsonify({'message': 'State updated successfully'})




# Delete a university by id
@app.route('/states/<string:state_name>/universities/<int:uni_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_university(state_name, uni_id):
    """
    Delete a university in a specific state by ID.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: uni_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: University deleted successfully
      404:
        description: State or university not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    university = University.query.filter_by(id=uni_id, state_id=state.id).first()
    if not university:
        return jsonify({'error': 'University not found in the specified state'}), 404

    db.session.delete(university)

    # Ensure university_number is at a minimum of 0
    state.university_number = max(0, state.university_number - 1)

    db.session.commit()

    return jsonify({'message': 'University deleted successfully'})





# Delete a university by name
@app.route('/states/<string:state_name>/universities/<string:uni_name>', methods=['DELETE'])
@login_required
@admin_required
def delete_university_by_name(state_name, uni_name):
    """
    Delete a university in a specific state by name.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: uni_name
        in: path
        type: integer
        required: true
    responses:
      200:
        description: University deleted successfully
      404:
        description: State or university not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    university = University.query.filter_by(name=uni_name, state_id=state.id).first()
    if not university:
        return jsonify({'error': 'University not found in the specified state'}), 404

    db.session.delete(university)
    state.university_number = max(0, state.university_number - 1)
    db.session.commit()
    return jsonify({'message': 'University deleted successfully'})






# Update a university
@app.route('/states/<string:state_name>/universities/<int:uni_id>', methods=['PUT'])
@login_required
@admin_required
def update_university(state_name, uni_id):
    """
    Update information about a university in a specific state by ID.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: uni_id
        in: path
        type: integer
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            location:
              type: string
            status:
              type: string
            tuition_fee:
              type: number
            specialty:
              type: string
            degree:
              type: string
            student_capacity:
              type: integer
            last_year_score:
              type: number
    responses:
      200:
        description: University updated successfully
      404:
        description: State or university not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    university = University.query.get(uni_id)
    if not university:
        return jsonify({'error': 'University not found'}), 404

    data = request.json
    university.name = data.get('name', university.name)
    university.description = data.get('description', university.description)
    university.location = data.get('location', university.location)
    university.status = data.get('status', university.status)
    university.tuition_fee = data.get('tuition_fee', university.tuition_fee)
    university.specialty = data.get('specialty', university.specialty)
    university.degree = data.get('degree', university.degree)
    university.student_capacity = data.get('student_capacity', university.student_capacity)  # Added
    university.last_year_score = data.get('last_year_score', university.last_year_score)  # Added

    db.session.commit()
    return jsonify({'message': 'University updated successfully'})






# Update a university by name
@app.route('/states/<string:state_name>/universities/<string:uni_name>', methods=['PUT'])
@login_required
@admin_required
def update_university_by_name(state_name, uni_name):
    """
    Update information about a university in a specific state by name.
    ---
    tags:
      - admin_only
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: uni_name
        in: path
        type: integer
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
            description:
              type: string
            location:
              type: string
            status:
              type: string
            tuition_fee:
              type: number
            specialty:
              type: string
            degree:
              type: string
            student_capacity:
              type: integer
            last_year_score:
              type: number
    responses:
      200:
        description: University updated successfully
      404:
        description: State or university not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    university = University.query.filter_by(name=uni_name, state_id=state.id).first()
    if not university:
        return jsonify({'error': 'University not found'}), 404

    data = request.json
    university.name = data.get('name', university.name)
    university.description = data.get('description', university.description)
    university.location = data.get('location', university.location)
    university.status = data.get('status', university.status)
    university.tuition_fee = data.get('tuition_fee', university.tuition_fee)
    university.specialty = data.get('specialty', university.specialty)
    university.degree = data.get('degree', university.degree)
    university.student_capacity = data.get('student_capacity', university.student_capacity)  # Added
    university.last_year_score = data.get('last_year_score', university.last_year_score)  # Added

    db.session.commit()
    return jsonify({'message': 'University updated successfully'})



# Get universities in a state by specialty
@app.route('/states/<string:state_name>/universities/specialty/<string:specialty>', methods=['GET'])
@login_required
def get_universities_in_state_by_speciality(state_name, specialty):
    """
    Get information about universities in a specific state based on specialty.
    ---
    tags:
      - filters
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: specialty
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities in the specified state and specialty
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              status:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              degree:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    universities = University.query.filter_by(state=state, specialty=specialty).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'status': uni.status,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'degree': uni.degree,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)


# Get universities in a state by status
@app.route('/states/<string:state_name>/universities/status/<string:status>', methods=['GET'])
@login_required
def get_universities_in_state_by_status(state_name, status):
    """
    Get information about universities in a specific state based on status.
    ---
    tags:
      - filters
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: status
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities in the specified state and status
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              specialty:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              degree:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    universities = University.query.filter_by(state=state, status=status).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'specialty': uni.specialty,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'degree': uni.degree,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)


# Get universities in a state by degree
@app.route('/states/<string:state_name>/universities/degree/<string:degree>', methods=['GET'])
@login_required
def get_universities_in_state_by_degree(state_name, degree):
    """
    Get information about universities in a specific state based on degree.
    ---
    tags:
      - filters
    parameters:
      - name: state_name
        in: path
        type: string
        required: true
      - name: degree
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities in the specified state and degree
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              status:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              specialty:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: State not found
    """
    state = State.query.filter_by(name=state_name).first()
    if not state:
        return jsonify({'error': 'State not found'}), 404

    universities = University.query.filter_by(state=state, degree=degree).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'status': uni.status,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'specialty': uni.specialty,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)




# Get universities by speciality
@app.route('/universities/specialty/<string:specialty>', methods=['GET'])
@login_required
def get_universities_by_speciality(specialty):
    """
    Get information about universities based on specialty.
    ---
    tags:
      - filters
    parameters:
      - name: specialty
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities with the specified specialty
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              state:
                type: string
              status:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              degree:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: No universities found with the specified specialty
    """
    universities = University.query.filter_by(specialty=specialty).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'state': uni.state.name,  # Include state information
                          'status': uni.status,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'degree': uni.degree,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)


# Get universities by status
@app.route('/universities/status/<string:status>', methods=['GET'])
@login_required
def get_universities_by_status(status):
    """
    Get information about universities based on status.
    ---
    tags:
      - filters
    parameters:
      - name: status
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities with the specified status
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              state:
                type: string
              specialty:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              degree:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: No universities found with the specified status
    """
    universities = University.query.filter_by(status=status).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'state': uni.state.name,  # Include state information
                          'specialty': uni.specialty,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'degree': uni.degree,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)


# Get universities by degree
@app.route('/universities/degree/<string:degree>', methods=['GET'])
@login_required
def get_universities_by_degree(degree):
    """
    Get information about universities based on degree.
    ---
    tags:
      - filters
    parameters:
      - name: degree
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of universities with the specified degree
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              state:
                type: string
              status:
                type: string
              description:
                type: string
              location:
                type: string
              tuition_fee:
                type: number
              specialty:
                type: string
              student_capacity:
                type: integer
              last_year_score:
                type: number
      404:
        description: No universities found with the specified degree
    """
    universities = University.query.filter_by(degree=degree).all()
    universities_list = [{'id': uni.id,
                          'name': uni.name,
                          'state': uni.state.name,  # Include state information
                          'status': uni.status,
                          'description': uni.description,
                          'location': uni.location,
                          'tuition_fee': uni.tuition_fee,
                          'specialty': uni.specialty,
                          'student_capacity': uni.student_capacity,
                          'last_year_score': uni.last_year_score}
                         for uni in universities]

    return jsonify(universities_list)


# Get a university by name
@app.route('/universities/name/<string:uni_name>', methods=['GET'])
@login_required
def get_university_by_name(uni_name):
    """
    Get information about a university by its name.
    ---
    tags:
      - filters
    parameters:
      - name: uni_name
        in: path
        type: string
        required: true
    responses:
      200:
        description: Information about the specified university
        schema:
          type: object
          properties:
            id:
              type: integer
            name:
              type: string
            state:
              type: string
            status:
              type: string
            description:
              type: string
            location:
              type: string
            tuition_fee:
              type: number
            specialty:
              type: string
            degree:
              type: string
            student_capacity:
              type: integer
            last_year_score:
              type: number
      404:
        description: University not found
    """

    university = University.query.filter_by(name=uni_name).first()
    if not university:
        return jsonify({'error': 'University not found'}), 404

    university_data = {
        'id': university.id,
        'name': university.name,
        'state': university.state.name,
        'status': university.status,
        'description': university.description,
        'location': university.location,
        'tuition_fee': university.tuition_fee,
        'specialty': university.specialty,
        'degree': university.degree,
        'student_capacity': university.student_capacity,
        'last_year_score': university.last_year_score
    }

    return jsonify(university_data)


if __name__ == '__main__':
    app.run(debug=True)
