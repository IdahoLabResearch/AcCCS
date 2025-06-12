from flask import Flask, render_template, request, jsonify
import os
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Anagram Solver Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host address to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on (default: 8000)')
    return parser.parse_args()

app = Flask(__name__, 
           template_folder='web',  # Use 'web' instead of 'templates'
           static_folder='web')    # Also serve static files from 'web'

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/process", methods=['POST'])
def processText():
    return None

if __name__ == "__main__":
    args = parse_args()
    app.run(host=args.host, port=args.port, debug=True)