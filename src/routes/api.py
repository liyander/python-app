from flask import Blueprint, request, jsonify

api = Blueprint('api', __name__)

@api.route('/detect', methods=['POST'])
def detect_phishing():
    data = request.get_json()
    # Here you would implement the logic to detect phishing using the data received
    # For now, we will return a mock response
    response = {
        'status': 'success',
        'message': 'Phishing detection logic not implemented yet.'
    }
    return jsonify(response), 200

@api.route('/status', methods=['GET'])
def status():
    return jsonify({'status': 'API is running'}), 200