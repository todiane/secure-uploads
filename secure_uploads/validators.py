# secure_uploads/validators.py
"""
Core validation functions for secure file uploads.
These can be used standalone or with the form mixins.
"""

import os
import uuid
import re
from io import BytesIO

from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible

from .config import (
    get_max_file_size,
    get_max_image_dimensions,
    get_min_image_dimensions,
    get_allowed_image_extensions,
    get_allowed_image_mime_types,
    get_allowed_document_extensions,
    get_allowed_document_mime_types,
    get_sanitise_filenames,
    get_blocked_url_hosts,
    get_require_https_urls,
)


# ============================================================================
# MIME TYPE DETECTION
# ============================================================================

def get_mime_type(file):
    """
    Detect MIME type by reading actual file content (magic bytes).
    Uses python-magic if available, falls back to manual detection.
    """
    file.seek(0)
    header = file.read(32)
    file.seek(0)
    
    # Try python-magic first (more reliable)
    try:
        import magic
        file.seek(0)
        mime = magic.from_buffer(file.read(2048), mime=True)
        file.seek(0)
        return mime
    except ImportError:
        pass
    
    # Fallback: Manual magic byte detection
    # JPEG
    if header[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    
    # PNG
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    
    # GIF
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    
    # WebP
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'image/webp'
    
    # PDF
    if header[:5] == b'%PDF-':
        return 'application/pdf'
    
    # BMP
    if header[:2] == b'BM':
        return 'image/bmp'
    
    # TIFF (little endian)
    if header[:4] == b'II*\x00':
        return 'image/tiff'
    
    # TIFF (big endian)
    if header[:4] == b'MM\x00*':
        return 'image/tiff'
    
    return 'application/octet-stream'


# ============================================================================
# FILENAME SANITISATION
# ============================================================================

def sanitise_filename(filename, preserve_original=False):
    """
    Sanitise a filename to prevent path traversal and other attacks.
    
    Args:
        filename: Original filename
        preserve_original: If True, clean the original name instead of replacing with UUID
    
    Returns:
        Safe filename string
    """
    # Get the extension
    ext = os.path.splitext(filename)[1].lower()
    
    if not preserve_original or not get_sanitise_filenames():
        # Generate a completely random safe filename
        return f"{uuid.uuid4().hex}{ext}"
    
    # Clean the original filename
    name = os.path.splitext(filename)[0]
    
    # Remove any path components
    name = os.path.basename(name)
    
    # Replace spaces and special chars with underscores
    name = re.sub(r'[^\w\-]', '_', name)
    
    # Remove multiple consecutive underscores
    name = re.sub(r'_+', '_', name)
    
    # Limit length
    name = name[:50]
    
    # Add UUID suffix for uniqueness
    return f"{name}_{uuid.uuid4().hex[:8]}{ext}"


# ============================================================================
# IMAGE VALIDATORS
# ============================================================================

def validate_file_size(file, max_size=None):
    """Validate file is under the maximum size."""
    if max_size is None:
        max_size = get_max_file_size()
    
    if file.size > max_size:
        max_mb = max_size / (1024 * 1024)
        file_mb = file.size / (1024 * 1024)
        raise ValidationError(
            f'File size ({file_mb:.1f}MB) exceeds maximum allowed ({max_mb:.1f}MB)'
        )


def validate_file_extension(file, allowed_extensions=None):
    """Validate file has an allowed extension."""
    if allowed_extensions is None:
        allowed_extensions = get_allowed_image_extensions()
    
    ext = os.path.splitext(file.name)[1].lower()
    
    if ext not in allowed_extensions:
        raise ValidationError(
            f'File type "{ext}" not allowed. Allowed types: {", ".join(allowed_extensions)}'
        )


def validate_mime_type(file, allowed_mime_types=None):
    """Validate file's actual content matches an allowed MIME type."""
    if allowed_mime_types is None:
        allowed_mime_types = get_allowed_image_mime_types()
    
    mime_type = get_mime_type(file)
    
    if mime_type not in allowed_mime_types:
        raise ValidationError(
            f'File content type "{mime_type}" not allowed. '
            f'Allowed types: {", ".join(allowed_mime_types)}'
        )


def validate_image_integrity(file):
    """
    Verify the file is actually a valid, non-corrupted image.
    Uses PIL to verify the image can be opened and processed.
    """
    try:
        from PIL import Image
        
        file.seek(0)
        img = Image.open(file)
        
        # verify() checks the file for errors
        img.verify()
        
        # Re-open because verify() can only be called once
        file.seek(0)
        img = Image.open(file)
        
        # Actually load the image data to ensure it's not truncated
        img.load()
        
        file.seek(0)
        return img.size  # Return dimensions for further validation
        
    except Exception as e:
        raise ValidationError(
            f'Invalid or corrupted image file: {str(e)}'
        )


def validate_image_dimensions(file, max_dimensions=None, min_dimensions=None):
    """Validate image dimensions are within acceptable range."""
    if max_dimensions is None:
        max_dimensions = get_max_image_dimensions()
    if min_dimensions is None:
        min_dimensions = get_min_image_dimensions()
    
    try:
        from PIL import Image
        
        file.seek(0)
        img = Image.open(file)
        width, height = img.size
        file.seek(0)
        
        max_width, max_height = max_dimensions
        min_width, min_height = min_dimensions
        
        if width > max_width or height > max_height:
            raise ValidationError(
                f'Image dimensions ({width}x{height}) exceed maximum '
                f'allowed ({max_width}x{max_height})'
            )
        
        if width < min_width or height < min_height:
            raise ValidationError(
                f'Image dimensions ({width}x{height}) below minimum '
                f'required ({min_width}x{min_height})'
            )
            
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f'Could not read image dimensions: {str(e)}')


def validate_no_embedded_content(file):
    """
    Check for potentially malicious embedded content in images.
    Detects things like PHP code, JavaScript, or shell commands hidden in metadata.
    """
    file.seek(0)
    content = file.read()
    file.seek(0)
    
    # Patterns that should never appear in legitimate image files
    suspicious_patterns = [
        b'<?php',
        b'<script',
        b'javascript:',
        b'onerror=',
        b'onload=',
        b'eval(',
        b'exec(',
        b'system(',
        b'shell_exec',
        b'passthru(',
        b'base64_decode',
        b'#!/bin/',
        b'#!/usr/',
        b'import os',
        b'import subprocess',
        b'__import__',
    ]
    
    content_lower = content.lower()
    
    for pattern in suspicious_patterns:
        if pattern.lower() in content_lower:
            raise ValidationError(
                'File contains suspicious content and cannot be uploaded'
            )


# ============================================================================
# COMPREHENSIVE IMAGE VALIDATOR
# ============================================================================

def validate_image_upload(file, max_size=None, allowed_extensions=None, 
                          allowed_mime_types=None, check_dimensions=True,
                          check_embedded_content=True):
    """
    Comprehensive image validation - runs all security checks.
    
    Args:
        file: The uploaded file object
        max_size: Maximum file size in bytes (uses config default if None)
        allowed_extensions: List of allowed extensions (uses config default if None)
        allowed_mime_types: List of allowed MIME types (uses config default if None)
        check_dimensions: Whether to validate image dimensions
        check_embedded_content: Whether to scan for malicious content
    
    Raises:
        ValidationError: If any validation fails
    
    Returns:
        True if all validations pass
    """
    # 1. File size
    validate_file_size(file, max_size)
    
    # 2. File extension
    validate_file_extension(file, allowed_extensions)
    
    # 3. MIME type (actual content check)
    if allowed_mime_types is None:
        allowed_mime_types = get_allowed_image_mime_types()
    validate_mime_type(file, allowed_mime_types)
    
    # 4. Image integrity (can PIL open it?)
    validate_image_integrity(file)
    
    # 5. Image dimensions
    if check_dimensions:
        validate_image_dimensions(file)
    
    # 6. Embedded malicious content
    if check_embedded_content:
        validate_no_embedded_content(file)
    
    return True


# ============================================================================
# DOCUMENT VALIDATOR (for PDFs, receipts, etc.)
# ============================================================================

def validate_document_upload(file, max_size=None, allowed_extensions=None,
                             allowed_mime_types=None):
    """
    Validate document uploads (PDFs, images for receipts, etc.)
    
    Args:
        file: The uploaded file object
        max_size: Maximum file size in bytes
        allowed_extensions: List of allowed extensions
        allowed_mime_types: List of allowed MIME types
    
    Raises:
        ValidationError: If any validation fails
    
    Returns:
        True if all validations pass
    """
    if allowed_extensions is None:
        allowed_extensions = get_allowed_document_extensions()
    if allowed_mime_types is None:
        allowed_mime_types = get_allowed_document_mime_types()
    
    # 1. File size
    validate_file_size(file, max_size)
    
    # 2. File extension
    validate_file_extension(file, allowed_extensions)
    
    # 3. MIME type
    validate_mime_type(file, allowed_mime_types)
    
    # 4. For images, also validate integrity
    mime_type = get_mime_type(file)
    if mime_type.startswith('image/'):
        validate_image_integrity(file)
        validate_no_embedded_content(file)
    
    # 5. For PDFs, basic validation
    if mime_type == 'application/pdf':
        validate_pdf_basic(file)
    
    return True


def validate_pdf_basic(file):
    """Basic PDF validation - checks structure and scans for JavaScript."""
    file.seek(0)
    content = file.read(10000)  # Read first 10KB
    file.seek(0)
    
    # Check PDF header
    if not content.startswith(b'%PDF-'):
        raise ValidationError('Invalid PDF file structure')
    
    # Check for JavaScript (can be malicious)
    if b'/JavaScript' in content or b'/JS' in content:
        raise ValidationError(
            'PDF files containing JavaScript are not allowed for security reasons'
        )
    
    # Check for embedded files/attachments
    if b'/EmbeddedFile' in content:
        raise ValidationError(
            'PDF files with embedded attachments are not allowed'
        )


# ============================================================================
# URL VALIDATOR (for external image URLs)
# ============================================================================

def validate_external_url(url, require_https=None, require_image_extension=True):
    """
    Validate an external URL for security (SSRF protection).
    
    Args:
        url: The URL to validate
        require_https: Whether to require HTTPS (uses config default if None)
        require_image_extension: Whether URL must end with image extension
    
    Raises:
        ValidationError: If URL is invalid or blocked
    
    Returns:
        True if URL is valid
    """
    from urllib.parse import urlparse
    
    if require_https is None:
        require_https = get_require_https_urls()
    
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError('Invalid URL format')
    
    # Check scheme
    if require_https and parsed.scheme != 'https':
        raise ValidationError('Only HTTPS URLs are allowed')
    
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError('Invalid URL scheme')
    
    # Check for blocked hosts (SSRF protection)
    blocked_hosts = get_blocked_url_hosts()
    netloc_lower = parsed.netloc.lower()
    
    for blocked in blocked_hosts:
        if netloc_lower == blocked or netloc_lower.startswith(blocked):
            raise ValidationError('This URL is not allowed')
    
    # Check for image extension if required
    if require_image_extension:
        allowed_exts = get_allowed_image_extensions()
        path_lower = parsed.path.lower()
        
        if not any(path_lower.endswith(ext) for ext in allowed_exts):
            raise ValidationError(
                f'URL must point to an image file ({", ".join(allowed_exts)})'
            )
    
    return True


# ============================================================================
# DJANGO MODEL FIELD VALIDATORS (for use in models.py)
# ============================================================================

@deconstructible
class SecureImageValidator:
    """
    Validator class for use with Django model ImageField.
    
    Usage in models.py:
        from secure_uploads.validators import SecureImageValidator
        
        image = models.ImageField(
            upload_to='images/',
            validators=[SecureImageValidator()]
        )
    """
    
    def __init__(self, max_size=None, allowed_extensions=None, 
                 allowed_mime_types=None, check_dimensions=True):
        self.max_size = max_size
        self.allowed_extensions = allowed_extensions
        self.allowed_mime_types = allowed_mime_types
        self.check_dimensions = check_dimensions
    
    def __call__(self, file):
        validate_image_upload(
            file,
            max_size=self.max_size,
            allowed_extensions=self.allowed_extensions,
            allowed_mime_types=self.allowed_mime_types,
            check_dimensions=self.check_dimensions
        )
    
    def __eq__(self, other):
        return (
            isinstance(other, SecureImageValidator) and
            self.max_size == other.max_size and
            self.allowed_extensions == other.allowed_extensions and
            self.allowed_mime_types == other.allowed_mime_types and
            self.check_dimensions == other.check_dimensions
        )


@deconstructible
class SecureDocumentValidator:
    """
    Validator class for use with Django model FileField.
    
    Usage in models.py:
        from secure_uploads.validators import SecureDocumentValidator
        
        receipt = models.FileField(
            upload_to='receipts/',
            validators=[SecureDocumentValidator()]
        )
    """
    
    def __init__(self, max_size=None, allowed_extensions=None, 
                 allowed_mime_types=None):
        self.max_size = max_size
        self.allowed_extensions = allowed_extensions
        self.allowed_mime_types = allowed_mime_types
    
    def __call__(self, file):
        validate_document_upload(
            file,
            max_size=self.max_size,
            allowed_extensions=self.allowed_extensions,
            allowed_mime_types=self.allowed_mime_types
        )
    
    def __eq__(self, other):
        return (
            isinstance(other, SecureDocumentValidator) and
            self.max_size == other.max_size and
            self.allowed_extensions == other.allowed_extensions and
            self.allowed_mime_types == other.allowed_mime_types
        )
