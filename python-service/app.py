from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    Returns a 200 OK status with a JSON body indicating the service is healthy.
    """
    return jsonify(status="UP", service="Python"), 200

@app.route('/metrics', methods=['GET'])
def metrics():
    """
    Basic metrics endpoint.
    In a real application, this would expose more meaningful metrics,
    possibly in Prometheus format.
    """
    # Example basic metrics
    # In a real scenario, you might use a library like prometheus_client
    return jsonify(
        service_name="PythonService",
        uptime_seconds=os.times().elapsed, # System-wide time, not process uptime
        requests_processed=123, # Dummy value
        errors_encountered=0 # Dummy value
    ), 200

if __name__ == '__main__':
    # Listen on all available IPs, port 5000 is Flask's default
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
