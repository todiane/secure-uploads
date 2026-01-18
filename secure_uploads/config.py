# secure_uploads/config.py
"""
Configuration for secure file uploads.
Override these in your Django settings.py by prefixing with SECURE_UPLOAD_

Example in settings.py:
    SECURE_UPLOAD_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    SECURE_UPLOAD_ALLOWED_IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png']
"""

from django.conf import settings

# Default configurations - override in your project's settings.py

def get_setting(name, default):
    """Get a setting from Django settings or return default."""
    return getattr(settings, f'SECURE_UPLOAD_{name}', default)


# ============================================================================
# FILE SIZE LIMITS
# ============================================================================

def get_max_file_size():
    """Maximum file size in bytes. Default: 5MB"""
    return get_setting('MAX_FILE_SIZE', 5 * 1024 * 1024)


def get_max_image_dimensions():
    """Maximum image dimensions (width, height). Default: 4096x4096"""
    return get_setting('MAX_IMAGE_DIMENSIONS', (4096, 4096))


def get_min_image_dimensions():
    """Minimum image dimensions (width, height). Default: 10x10"""
    return get_setting('MIN_IMAGE_DIMENSIONS', (10, 10))


# ============================================================================
# ALLOWED FILE TYPES - IMAGES
# ============================================================================

def get_allowed_image_extensions():
    """Allowed image file extensions."""
    return get_setting('ALLOWED_IMAGE_EXTENSIONS', [
        '.jpg', '.jpeg', '.png', '.webp', '.gif'
    ])


def get_allowed_image_mime_types():
    """Allowed image MIME types (verified by reading file content)."""
    return get_setting('ALLOWED_IMAGE_MIME_TYPES', [
        'image/jpeg',
        'image/png', 
        'image/webp',
        'image/gif'
    ])


# ============================================================================
# ALLOWED FILE TYPES - DOCUMENTS (for receipt uploads etc.)
# ============================================================================

def get_allowed_document_extensions():
    """Allowed document file extensions."""
    return get_setting('ALLOWED_DOCUMENT_EXTENSIONS', [
        '.pdf', '.jpg', '.jpeg', '.png', '.webp'
    ])


def get_allowed_document_mime_types():
    """Allowed document MIME types."""
    return get_setting('ALLOWED_DOCUMENT_MIME_TYPES', [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'image/webp'
    ])


# ============================================================================
# SECURITY SETTINGS
# ============================================================================

def get_sanitise_filenames():
    """Whether to replace original filenames with UUIDs. Default: True"""
    return get_setting('SANITISE_FILENAMES', True)


def get_blocked_url_hosts():
    """Hosts to block for external URL validation (SSRF protection)."""
    return get_setting('BLOCKED_URL_HOSTS', [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '10.',
        '192.168.',
        '172.16.',
        '172.17.',
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',
        '169.254.',
        '[::1]',
        'metadata.google',
        '169.254.169.254',  # AWS/GCP metadata endpoint
    ])


def get_require_https_urls():
    """Whether to require HTTPS for external URLs. Default: True"""
    return get_setting('REQUIRE_HTTPS_URLS', True)


# ============================================================================
# QUICK ACCESS TO ALL SETTINGS
# ============================================================================

def get_all_settings():
    """Return all settings as a dictionary for debugging."""
    return {
        'MAX_FILE_SIZE': get_max_file_size(),
        'MAX_IMAGE_DIMENSIONS': get_max_image_dimensions(),
        'MIN_IMAGE_DIMENSIONS': get_min_image_dimensions(),
        'ALLOWED_IMAGE_EXTENSIONS': get_allowed_image_extensions(),
        'ALLOWED_IMAGE_MIME_TYPES': get_allowed_image_mime_types(),
        'ALLOWED_DOCUMENT_EXTENSIONS': get_allowed_document_extensions(),
        'ALLOWED_DOCUMENT_MIME_TYPES': get_allowed_document_mime_types(),
        'SANITISE_FILENAMES': get_sanitise_filenames(),
        'BLOCKED_URL_HOSTS': get_blocked_url_hosts(),
        'REQUIRE_HTTPS_URLS': get_require_https_urls(),
    }
