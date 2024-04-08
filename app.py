from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_pymongo import PyMongo
from datetime import datetime
from bson import ObjectId
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

from flask_bcrypt import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'  # Replace this with your own secret key

app.config["MONGO_URI"] = "mongodb://localhost:27017/mydatabase"
db = PyMongo(app).db



# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)

# User model for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader 
def load_user(user_id): 
    user_data = db.Users.find_one({"_id": ObjectId(user_id)}) 
    if user_data: 
        user = User() 
        user.id = str(user_data['_id']) 
        user.username = user_data['username']  # Set the username attribute 
        return user 
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get registration form data
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
        if db.Users.find_one({"username": username}):
            return render_template('register.html', error='Username already exists')

        # Hash the password
        hashed_password = generate_password_hash(password).decode('utf-8')

        # Store user details in the database
        db.Users.insert_one({"username": username, "password": hashed_password})

        # Redirect to login page after successful registration
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve user data from the database
        user_data = db.Users.find_one({"username": username})

        if user_data and check_password_hash(user_data['password'], password):
            # Authentication successful, load user object and login
            user = User()
            user.id = str(user_data['_id'])
            login_user(user)

            # Redirect to index or dashboard
            return redirect(url_for('index'))
        else:
            # Authentication failed, show login page with error message
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST']) 
def index(): 
    if not current_user.is_authenticated: 
        return redirect(url_for('login')) 
     
    # Retrieve all documents from the MongoDB collection 
    all_data = db.Demo.find() 
 
    # Convert cursor to a list for easy iteration in the template 
    all_data_list = list(all_data) 
 
    # Get unique values for 'Day', 'Time', and 'Class' from the collection 
    unique_days = db.Demo.distinct('Day') 
    unique_times = db.Demo.distinct('StartTime') 
    unique_classes = db.Demo.distinct('Class') 
     
    # Sort the unique_days list so that Monday appears at the top 
    unique_days.sort(key=lambda x: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].index(x)) 
 
    selected_lecture = None 
 
    if request.method == 'POST': 
        # Get selected day, time, and class from the form 
        selected_day = request.form.get('day') 
        selected_time = request.form.get('time') 
        selected_class = request.form.get('class') 
 
        # Query MongoDB for the selected lecture 
        selected_lecture_query = {'Day': selected_day, 'StartTime': selected_time, 'Class': selected_class} 
        selected_lecture = db.Demo.find_one(selected_lecture_query) 
 
    # Get current day and time 
    now = datetime.now() 
    current_day = now.strftime('%A') 
    current_time_24hr = now.strftime('%H:%M') 
 
    # Query MongoDB for lectures currently ongoing 
    current_lectures_query = { 
        'Day': current_day, 
        'StartTime': {'$lte': current_time_24hr}, 
        'EndTime': {'$gt': current_time_24hr} 
    } 
    current_lectures = db.Demo.find(current_lectures_query) 
 
    # Query MongoDB for all lectures with the same day and time as the selected lecture 
    if selected_lecture: 
        same_time_lectures_query = { 
            'Day': selected_lecture['Day'], 
            'StartTime': selected_lecture['StartTime'] 
        } 
        same_time_lectures = db.Demo.find(same_time_lectures_query) 
    else: 
        same_time_lectures = None 
 
    # Pass the variables to the template, including current_user, current_day, and current_time_24hr 
    return render_template('index.html', all_data=all_data_list, selected_lecture=selected_lecture, 
                           unique_days=unique_days, unique_times=unique_times, unique_classes=unique_classes, 
                           current_lectures=current_lectures, same_time_lectures=same_time_lectures, 
                           current_user=current_user, current_day=current_day, current_time_24hr=current_time_24hr)

@app.route('/Aiml6_lectures', methods=['GET', 'POST'])
def Aiml6_lectures():
    # Retrieve all documents from the MongoDB collection for CSE lectures
    all_cse_data = db.Aiml6_Lectures.find()

    # Convert cursor to a list for easy iteration in the template
    all_cse_data_list = list(all_cse_data)

    # Get unique values for 'Day' and 'Time' from the collection
    unique_cse_days = db.Aiml6_Lectures.distinct('Day')
    unique_cse_times = db.Aiml6_Lectures.distinct('StartTime')

    selected_cse_lecture = None
    unique_cse_days.sort(key=lambda x: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].index(x)) 
    if request.method == 'POST':
        # Get selected day and time from the forms
        selected_cse_day = request.form.get('day')
        selected_cse_time = request.form.get('time')

        # Query MongoDB for the selected lecture
        selected_cse_lecture_query = {'Day': selected_cse_day, 'StartTime': selected_cse_time}
        selected_cse_lecture = db.Aiml6_Lectures.find_one(selected_cse_lecture_query)

    # Get current day and time
    current_cse_day = datetime.now().strftime('%A')
    current_cse_time_24hr = datetime.now().strftime('%H:%M')

    # Query MongoDB for lectures currently ongoing
    current_cse_lectures_query = {
        'Day': current_cse_day,
        'StartTime': {'$lte': current_cse_time_24hr},
        'EndTime': {'$gt': current_cse_time_24hr}
    }
    current_cse_lectures = db.Aiml6_Lectures.find(current_cse_lectures_query)

    # Query MongoDB for all lectures with the same day and time as the selected lecture
    if selected_cse_lecture:
        same_time_cse_lectures_query = {
            'Day': selected_cse_lecture['Day'],
            'StartTime': selected_cse_lecture['StartTime']
        }
        same_time_cse_lectures = db.Aiml6_Lectures.find(same_time_cse_lectures_query)
    else:
        same_time_cse_lectures = None

    # Pass the variables to the template
    return render_template('Aiml6_lectures.html', all_cse_data=all_cse_data_list, selected_cse_lecture=selected_cse_lecture,
                           unique_cse_days=unique_cse_days, unique_cse_times=unique_cse_times,
                           current_cse_lectures=current_cse_lectures, same_time_cse_lectures=same_time_cse_lectures)

@app.route('/cse4_lectures', methods=['GET', 'POST'])
def cse4_lectures():
    # Retrieve all documents from the MongoDB collection for CSE lectures
    all_cse_data = db.cse4_lectures.find()

    # Convert cursor to a list for easy iteration in the template
    all_cse_data_list = list(all_cse_data)

    # Get unique values for 'Day' and 'Time' from the collection
    unique_cse_days = db.cse4_lectures.distinct('Day')
    unique_cse_times = db.cse4_lectures.distinct('StartTime')

    selected_cse_lecture = None

    if request.method == 'POST':
        # Get selected day and time from the forms
        selected_cse_day = request.form.get('day')
        selected_cse_time = request.form.get('time')

        # Query MongoDB for the selected lecture
        selected_cse_lecture_query = {'Day': selected_cse_day, 'StartTime': selected_cse_time}
        selected_cse_lecture = db.cse4_lectures.find_one(selected_cse_lecture_query)

    # Get current day and time
    current_cse_day = datetime.now().strftime('%A')
    current_cse_time_24hr = datetime.now().strftime('%H:%M')

    # Query MongoDB for lectures currently ongoing
    current_cse_lectures_query = {
        'Day': current_cse_day,
        'StartTime': {'$lte': current_cse_time_24hr},
        'EndTime': {'$gt': current_cse_time_24hr}
    }
    current_cse_lectures = db.cse4_lectures.find(current_cse_lectures_query)

    # Query MongoDB for all lectures with the same day and time as the selected lecture
    if selected_cse_lecture:
        same_time_cse_lectures_query = {
            'Day': selected_cse_lecture['Day'],
            'StartTime': selected_cse_lecture['StartTime']
        }
        same_time_cse_lectures = db.cse4_lectures.find(same_time_cse_lectures_query)
    else:
        same_time_cse_lectures = None

    # Pass the variables to the template
    return render_template('cse4_lectures.html', all_cse_data=all_cse_data_list, selected_cse_lecture=selected_cse_lecture,
                           unique_cse_days=unique_cse_days, unique_cse_times=unique_cse_times,
                           current_cse_lectures=current_cse_lectures, same_time_cse_lectures=same_time_cse_lectures)

@app.route('/cse_lectures', methods=['GET', 'POST'])
def cse_lectures():
    # Retrieve all documents from the MongoDB collection for CSE lectures
    all_cse_data = db.CSE_SAM_6_Lectures.find()

    # Convert cursor to a list for easy iteration in the template
    all_cse_data_list = list(all_cse_data)

    # Get unique values for 'Day' and 'Time' from the collection
    unique_cse_days = db.CSE_SAM_6_Lectures.distinct('Day')
    unique_cse_times = db.CSE_SAM_6_Lectures.distinct('StartTime')

    selected_cse_lecture = None

    if request.method == 'POST':
        # Get selected day and time from the forms
        selected_cse_day = request.form.get('day')
        selected_cse_time = request.form.get('time')

        # Query MongoDB for the selected lecture
        selected_cse_lecture_query = {'Day': selected_cse_day, 'StartTime': selected_cse_time}
        selected_cse_lecture = db.CSE_SAM_6_Lectures.find_one(selected_cse_lecture_query)

    # Get current day and time
    current_cse_day = datetime.now().strftime('%A')
    current_cse_time_24hr = datetime.now().strftime('%H:%M')

    # Query MongoDB for lectures currently ongoing
    current_cse_lectures_query = {
        'Day': current_cse_day,
        'StartTime': {'$lte': current_cse_time_24hr},
        'EndTime': {'$gt': current_cse_time_24hr}
    }
    current_cse_lectures = db.CSE_SAM_6_Lectures.find(current_cse_lectures_query)

    # Query MongoDB for all lectures with the same day and time as the selected lecture
    if selected_cse_lecture:
        same_time_cse_lectures_query = {
            'Day': selected_cse_lecture['Day'],
            'StartTime': selected_cse_lecture['StartTime']
        }
        same_time_cse_lectures = db.CSE_SAM_6_Lectures.find(same_time_cse_lectures_query)
    else:
        same_time_cse_lectures = None

    # Pass the variables to the template
    return render_template('cse_lectures.html', all_cse_data=all_cse_data_list, selected_cse_lecture=selected_cse_lecture,
                           unique_cse_days=unique_cse_days, unique_cse_times=unique_cse_times,
                           current_cse_lectures=current_cse_lectures, same_time_cse_lectures=same_time_cse_lectures)


@app.route('/bsc6_lectures', methods=['GET', 'POST'])
def bsc6_lecture():
    # Retrieve all documents from the MongoDB collection for CSE lectures
    all_cse_data = db.bsc6_lecture.find()

    # Convert cursor to a list for easy iteration in the template
    all_cse_data_list = list(all_cse_data)

    # Get unique values for 'Day' and 'Time' from the collection
    unique_cse_days = db.bsc6_lecture.distinct('Day')
    unique_cse_times = db.bsc6_lecture.distinct('StartTime')

    selected_cse_lecture = None

    if request.method == 'POST':
        # Get selected day and time from the forms
        selected_cse_day = request.form.get('day')
        selected_cse_time = request.form.get('time')

        # Query MongoDB for the selected lecture
        selected_cse_lecture_query = {'Day': selected_cse_day, 'StartTime': selected_cse_time}
        selected_cse_lecture = db.bsc6_Lecture.find_one(selected_cse_lecture_query)

    # Get current day and time
    current_cse_day = datetime.now().strftime('%A')
    current_cse_time_24hr = datetime.now().strftime('%H:%M')

    # Query MongoDB for lectures currently ongoing
    current_cse_lectures_query = {
        'Day': current_cse_day,
        'StartTime': {'$lte': current_cse_time_24hr},
        'EndTime': {'$gt': current_cse_time_24hr}
    }
    current_cse_lectures = db.bsc6_lecture.find(current_cse_lectures_query)

    # Query MongoDB for all lectures with the same day and time as the selected lecture
    if selected_cse_lecture:
        same_time_cse_lectures_query = {
            'Day': selected_cse_lecture['Day'],
            'StartTime': selected_cse_lecture['StartTime']
        }
        same_time_cse_lectures = db.bsc6_lecture.find(same_time_cse_lectures_query)
    else:
        same_time_cse_lectures = None

    # Pass the variables to the template
    return render_template('bsc6_lectures.html', all_cse_data=all_cse_data_list, selected_cse_lecture=selected_cse_lecture,
                           unique_cse_days=unique_cse_days, unique_cse_times=unique_cse_times,
                           current_cse_lectures=current_cse_lectures, same_time_cse_lectures=same_time_cse_lectures)
@app.route('/faculty')
def faculty():
    # Retrieve faculty data from MongoDB collection
    faculty_data = db.Demo.find()

    # Extract unique faculty names from the data where the 'Faculty' field exists
    faculty_set = {doc.get("Faculty") for doc in faculty_data if "Faculty" in doc}

    # Convert set to list
    faculty_list = list(faculty_set)

    return render_template('faculty.html', faculty_list=faculty_list)

@app.route('/particular_classes') 
def particular_classes(): 
    return render_template('particular_classes.html')

@app.route('/get_lectures', methods=['POST'])
def get_lectures():
    try:
        faculty_name = request.form.get('faculty')
        current_time_24hr = datetime.now().strftime('%H:%M')
        
        # Query for current lectures including the 'Class' field
        current_lectures = list(db.Demo.find({'Faculty': faculty_name, 'StartTime': {'$lte': current_time_24hr}, 'EndTime': {'$gt': current_time_24hr}}, {'_id': 0}))
        
        # Query for all lectures including the 'Class' field
        all_lectures = list(db.Demo.find({'Faculty': faculty_name}, {'_id': 0}))
        
        lecture_data = {
            'current_lectures': current_lectures,
            'all_lectures': all_lectures
        }
        return jsonify(lecture_data)
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'An error occurred'}), 500
    
if __name__ == "__main__":
    app.run(debug=True, port=5001)

