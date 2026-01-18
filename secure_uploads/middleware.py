# secure_uploads/middleware.py
"""
Middleware for additional upload security at the request level.
"""

from django.conf import settings
from django.http import HttpResponseBadRequest
from .config import get_max_file_size


class SecureUploadMiddleware:
    """
    Middleware that enforces upload limits at the request level.
    
    This catches oversized uploads before they hit your views,
    preventing memory exhaustion attacks.
    
    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'secure_uploads.middleware.SecureUploadMiddleware',
            ...
        ]
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check Content-Length header for POST/PUT requests
        if request.method in ('POST', 'PUT', 'PATCH'):
            content_length = request.META.get('CONTENT_LENGTH')
            
            if content_length:
                try:
                    content_length = int(content_length)
                    max_size = get_max_file_size()
                    
                    # Allow some overhead for form data
                    max_request_size = max_size + (1024 * 1024)  # +1MB for form fields
                    
                    if content_length > max_request_size:
                        return HttpResponseBadRequest(
                            f'Request too large. Maximum size: {max_size // (1024*1024)}MB'
                        )
                except ValueError:
                    pass
        
        response = self.get_response(request)
        return response


class ContentSecurityMiddleware:
    """
    Middleware that adds security headers for uploaded content.
    
    Adds headers that prevent uploaded files from being executed
    or used in XSS attacks.
    
    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'secure_uploads.middleware.ContentSecurityMiddleware',
            ...
        ]
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Paths that serve uploaded content
        self.upload_paths = getattr(
            settings, 
            'SECURE_UPLOAD_MEDIA_PATHS',
            ['/media/', '/uploads/']
        )
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers for upload paths
        if any(request.path.startswith(path) for path in self.upload_paths):
            # Prevent content type sniffing
            response['X-Content-Type-Options'] = 'nosniff'
            
            # Prevent files from being rendered as HTML
            response['X-Download-Options'] = 'noopen'
            
            # Force download for potentially dangerous content types
            content_type = response.get('Content-Type', '')
            if content_type in ['application/octet-stream', 'text/html', 'text/plain']:
                response['Content-Disposition'] = 'attachment'
            
            # Strict CSP for uploaded content
            response['Content-Security-Policy'] = "default-src 'none'"
        
        return response
