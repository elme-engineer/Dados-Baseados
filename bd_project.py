import flask
import ast
import logging
import psycopg2
import uuid
import time
import bcrypt
from flask import jsonify, request, Flask
import hmac, hashlib, base64, json
from datetime import datetime, timedelta

app = flask.Flask(__name__)

StatusCodes = {
    'success': 200,
    'client_error': 400,
    'unauthorized': 401,
    'internal_error': 500
}


secret_key = '5e8d5172e0f21a9e5069f2d31514e028520eb0a25b85fdb4bbaf13649ff19f48'


##########################################################
## DATABASE ACCESS
##########################################################


def db_connection():
    db = psycopg2.connect(
        user='projectUser',
        password='project123',
        host='127.0.0.1',
        port='5432',
        database='project'
    )

    return db

@app.route('/')
def landing_page():
    return """

    Welcome to my BD project!  <br/>
    <br/>
    BD 2023-2024 Pedro Bento<br/>
    <br/>
    """

def generate_token(payload):
    # Ensure payload is JSON-encoded and then encoded to bytes
    payload_bytes = json.dumps(payload).encode()

    # Create header
    header = json.dumps({
        'typ': 'JWT',
        'alg': 'HS256'
    }).encode()
    b64_header = base64.urlsafe_b64encode(header).rstrip(b'=').decode()

    # Base64URL encode the payload
    b64_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()

    # Create signature
    signature = hmac.new(
        key=secret_key.encode(),
        msg=f'{b64_header}.{b64_payload}'.encode(),
        digestmod=hashlib.sha256
    ).digest()
    b64_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

    # Combine header, payload, and signature to form the JWT
    jwt = f'{b64_header}.{b64_payload}.{b64_signature}'
    return jwt


def descode_token(jwt):
    try:
        b64_header, b64_payload, b64_signature = jwt.split('.')

        # Verify the signature
        signature_checker = hmac.new(
            key=secret_key.encode(),
            msg=f'{b64_header}.{b64_payload}'.encode(),
            digestmod=hashlib.sha256
        ).digest()
        b64_signature_checker = base64.urlsafe_b64encode(signature_checker).rstrip(b'=').decode()

        if b64_signature_checker != b64_signature:
            raise Exception('Invalid signature')

        # Decode payload
        payload = json.loads(base64.urlsafe_b64decode(b64_payload + '=='))
        return payload

    except Exception as e:
        raise Exception(f'Token decoding failed: {e}')


@app.route('/dbproj/user', methods=['PUT'])
def autenticate_user():


    try:
        conn = db_connection()
        cur = conn.cursor()

        payload = request.get_json()

        if not payload or "username" not in payload or "password" not in payload:
            return jsonify({'results': 'missing values in payload'}), StatusCodes['client_error']

        username = payload["username"]
        password = payload["password"]

        # Use parameterized queries to prevent SQL injection
        query = """SELECT person_id, password FROM person WHERE username = %s;"""
        cur.execute(query, (username,))
        row = cur.fetchone()

        if row:
            user_id, hashed_password_from_db = row
            # Check if the provided password matches the hashed password from the database
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db.encode('utf-8')):
                token_payload = {'user_id': user_id}
                token = generate_token(token_payload)
                return jsonify({'token': token}), StatusCodes['success']
            else:
                return jsonify({'results': 'invalid'}), StatusCodes['unauthorized']
        else:
            return jsonify({'results': 'invalid'}), StatusCodes['unauthorized']

    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({'error': str(error)}), StatusCodes['internal_error']
    finally:
        if conn is not None:
            conn.close()


@app.route('/dbproj/register/<role>', methods=['POST'])
def add_person(role):

    logger.info('POST /register/<role>')
    payload = flask.request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    logger.debug(f'POST /register/<role> - payload: {payload}')

    # Validate role
    if role not in ['patient', 'doctor', 'nurse', 'assistant']:
        response = {'status': StatusCodes['client_error'], 'results': 'wrong role'}
        return jsonify(response)


   # Validate payload
    required_fields = ['name', 'age', 'username', 'password', 'address', 'phone_number']
    if not all(field in payload for field in required_fields):
        response = {'status': StatusCodes['client_error'], 'results': 'values missing in payload'}
        return jsonify(response)

    if 'email' not in payload:
        payload['email'] = "-"


    # Generate a unique person_id
    payload['person_id'] = str(uuid.uuid4())

    #encrypt password

    password = payload['password'];
    # Hash password    
    # Hash password    
    pwd_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    print(pwd_hash)

    # Insert into person table
    person_statement = '''
        INSERT INTO person (person_id, name, age, username, password, address, phone_number, email)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    '''
    person_values = (
        payload['person_id'], payload['name'], int(payload['age']), payload['username'], 
        pwd_hash, payload['address'], payload['phone_number'], payload['email']
    )
    
    try:
        
        cur.execute(person_statement, person_values)

        # Role-specific insertion
        if role == 'patient':
            if 'health_condition' not in payload:
                response = {'status': StatusCodes['client_error'], 'results': 'health_condition missing for patient'}
                return jsonify(response)

            patient_statement = 'INSERT INTO patient (person_person_id, health_condition) VALUES (%s, %s)'
            patient_values = (payload['person_id'], payload['health_condition'])
            cur.execute(patient_statement, patient_values)

        else:    #employee 

            if 'medical_license' not in payload:
                response = {'status': StatusCodes['client_error'], 'results': 'medical_license missing'}
                return jsonify(response)

        
            employee_statement = 'INSERT INTO employee (person_person_id, medical_license) VALUES (%s, %s)'
            employee_values = (payload['person_id'], payload['medical_license'])
            cur.execute(employee_statement, employee_values)

            if role == 'doctor':
                if 'category' not in payload:
                    response = {'status': StatusCodes['client_error'], 'results': 'category missing for doctor'}
                    return jsonify(response)

            

                doctor_statement = 'INSERT INTO doctor (employee_person_person_id, category) VALUES (%s, %s)'
                doctor_values = (payload['person_id'], payload['category'])
                cur.execute(doctor_statement, doctor_values)

            if role == 'nurse':
                if 'category' not in payload:
                    response = {'status': StatusCodes['client_error'], 'results': 'category missing for nurse'}
                    return jsonify(response)


                nurse_statement = 'INSERT INTO nurse (employee_person_person_id, category) VALUES (%s, %s)'
                nurse_values = (payload['person_id'], payload['category'])
                cur.execute(nurse_statement, nurse_values)


            if role == 'assistant':
                if 'area_of_work' not in payload:
                    response = {'status': StatusCodes['client_error'], 'results': 'area_of_work missing for assistant'}
                    return jsonify(response)

    
                assistant_statement = 'INSERT INTO assistent (employee_person_person_id, area_of_work) VALUES (%s, %s)'
                assistant_values = (payload['person_id'], payload['area_of_work'])
                cur.execute(assistant_statement, assistant_values)



        # Commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Inserted {role} with ID {payload["person_id"]}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /register/<role> - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)



if __name__ == '__main__':

    # set up logging
    logging.basicConfig(filename='log_file.log')
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s', '%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    host = '127.0.0.1'
    port = 8080
    app.run(host=host, debug=True, threaded=True, port=port)
    logger.info(f'API v1.0 online: http://{host}:{port}')