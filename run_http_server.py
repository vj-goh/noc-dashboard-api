#!/usr/bin/env python3
"""
Simple HTTP Server Wrapper for FastAPI
Wraps the FastAPI app to serve over HTTP directly
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import the FastAPI app
from app.main import app

# Create a test client
test_client = TestClient(app)

class FastAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler that forwards requests to FastAPI via TestClient"""
    
    def do_GET(self):
        self.handle_request('GET')
    
    def do_POST(self):
        self.handle_request('POST')
    
    def do_DELETE(self):
        self.handle_request('DELETE')
    
    def do_PUT(self):
        self.handle_request('PUT')
    
    def handle_request(self, method):
        try:
            # Extract path and query string
            path = self.path
            
            # Read body if present
            content_length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Forward request to FastAPI app
            response = test_client.request(method, path, content=body)
            
            # Send response
            self.send_response(response.status_code)
            
            # Send response headers
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.end_headers()
            
            # Send response body
            self.wfile.write(response.content)
            
            logger.info(f"{method} {path} -> {response.status_code}")
            
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

if __name__ == '__main__':
    host = '0.0.0.0'
    port = 3000
    
    server = HTTPServer((host, port), FastAPIHandler)
    logger.info(f"Starting HTTP server on {host}:{port}")
    logger.info("FastAPI app loaded via TestClient wrapper")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped")
