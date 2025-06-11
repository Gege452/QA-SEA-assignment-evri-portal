# Disclaimer

This application is a student project developed as part of a university assignment. It does not reflect the actual systems, processes, or technologies used by EVRi. While it is inspired by research into courier operations, the design, validation rules, and overall implementation have been created independently to satisfy academic criteria.


# EVRi Courier Portal (Flask Web App)

This is a role-based courier management and feedback web application for EVRi, built with Flask, SQLAlchemy, and Bootstrap.


## How to Run the Application locally

You will need to pull/download this repository and run the following commands below in cmd. (You will have to replace path\to with the actual path to the folder)

```bash
cd "path\to\QA-SEA-assignment-evri-portal"
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open your browser and go to:

```
http://127.0.0.1:5000/
```

## Dummy Data Setup

The application will come with Dummy Data. However, this dummy data was inserted into the database automatically with the seed.py script.

To populate the app with 10 courier admins, 10 couriers, and 30 feedback entries do the following:

You will need to pull/download this repository and run the following commands below in cmd. (You will have to replace path\to with the actual path to the folder)

```bash
cd "path\to\QA-SEA-assignment-evri-portal"
venv\Scripts\activate
pip install -r requirements.txt
python seed.py
```

## User Roles

- **Courier Admins**
  - Email must end in `@evri.com`
  - Full CRUD on courier accounts
  - View all submitted courier feedback

- **Couriers**
  - Login using auto-assigned Courier ID + 4-digit PIN
  - Can view and update their own profile
  - Can submit, edit, and delete feedback entries

## Libraries and Technologies Used

- Python 3.9+
- Flask
- Flask-Login
- Flask-SQLAlchemy
- Bootstrap 5
- SQLite
- Faker (for seeding)

