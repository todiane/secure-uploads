# Secure Uploads for Django

A drop-in module that adds comprehensive file upload security to any Django project. Protects against:

- **Malicious file uploads** disguised as images
- **Path traversal attacks** via crafted filenames
- **SSRF attacks** via external URL fields
- **Memory exhaustion** via oversized uploads
- **Embedded malicious content** in images
- **JavaScript in PDFs**

This is a lightweight, drop-in module that adds defensive file upload security to any Django project.

This module focuses on preventing common and costly upload-related vulnerabilities, including malicious files disguised as images, unsafe PDFs, SSRF attacks via external URLs, and resource exhaustion from oversized uploads.

I created it to protect my eCommerce builder and thought it would be useful here for whenever it is needed.

## Why this exists

This module was created after a real production incident.
A site I set up went down for several hours due to a subtle upload-related issue that wasn’t immediately obvious from logs or infrastructure checks. The problem wasn’t Django itself — it was a lack of consistent, defensive validation around uploads.

This folder is the result of turning that failure into a reusable safeguard. It exists so upload security is explicit, repeatable and 
easy to apply.

## Quick Start

### 1. Copy the module to your project

Copy the entire `secure_uploads` folder to your Django project root (alongside your apps).

### 2. Install dependencies

```bash
pip install Pillow
pip install python-magic  # Optional but recommended - better MIME detection
```

**Note:** On Windows, python-magic requires additional setup. The module works without it using fallback detection.

### 3. Add to settings.py (optional customisation)

All settings are optional and overrideable in settings.py:

```SECURE_UPLOAD_MAX_FILE_SIZE = 5 * 1024 * 1024
SECURE_UPLOAD_ALLOWED_IMAGE_EXTENSIONS = ['.jpg', '.png', '.webp']
SECURE_UPLOAD_REQUIRE_HTTPS_URLS = True
```

Sensible defaults are provided if nothing is configured.

```python
# File size limits
SECURE_UPLOAD_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB (default)

# Image settings
SECURE_UPLOAD_MAX_IMAGE_DIMENSIONS = (4096, 4096)  # Default
SECURE_UPLOAD_MIN_IMAGE_DIMENSIONS = (10, 10)  # Default

# Allowed types
SECURE_UPLOAD_ALLOWED_IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.gif']
SECURE_UPLOAD_ALLOWED_IMAGE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']

# Document settings (for PDFs, receipts, etc.)
SECURE_UPLOAD_ALLOWED_DOCUMENT_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png', '.webp']
SECURE_UPLOAD_ALLOWED_DOCUMENT_MIME_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp']

# Security
SECURE_UPLOAD_SANITISE_FILENAMES = True  # Replace filenames with UUIDs
SECURE_UPLOAD_REQUIRE_HTTPS_URLS = True  # Require HTTPS for external URLs
```

### 4. Add middleware (optional and recommended)

For additional protection at the request level:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'secure_uploads.middleware.SecureUploadMiddleware',  # Add early
    'secure_uploads.middleware.ContentSecurityMiddleware',  # Add for media paths
    # ... rest of your middleware
]
```
This blocks oversized uploads early and adds safe headers to uploaded content.
---

## Usage

### Method 1: Form Mixin (Recommended for ModelForms)

Use the provided form mixin to secure uploads without rewriting your forms. The easiest way to add security to existing forms:

```python
from django import forms
from secure_uploads.forms import SecureUploadMixin
from .models import Location

class LocationForm(SecureUploadMixin, forms.ModelForm):
    # Specify which fields contain uploads
    image_fields = ['image', 'thumbnail']
    url_fields = ['external_image_url']
    
    class Meta:
        model = Location
        fields = ['title', 'image', 'thumbnail', 'external_image_url']
```

**With custom settings per field:**

```python
class LocationForm(SecureUploadMixin, forms.ModelForm):
    image_fields = ['image', 'thumbnail']
    
    # Custom limits per field
    image_field_settings = {
        'image': {'max_size': 10 * 1024 * 1024},  # 10MB for main image
        'thumbnail': {'max_size': 1 * 1024 * 1024},  # 1MB for thumbnail
    }
    
    class Meta:
        model = Location
        fields = ['title', 'image', 'thumbnail']
```
This automatically applies:
- file size limits
- MIME verification
- extension checks
- filename sanitisation
- SSRF protection for URLs

### Method 2: Secure Form Fields

Replace standard Django fields with secure versions:

```python
from django import forms
from secure_uploads.forms import SecureImageField, SecureFileField, SecureURLField

class MyForm(forms.Form):
    profile_photo = SecureImageField(
        max_size=2 * 1024 * 1024,  # 2MB
        allowed_extensions=['.jpg', '.png'],
    )
    
    receipt = SecureFileField(
        max_size=5 * 1024 * 1024,
        allowed_extensions=['.pdf', '.jpg', '.png'],
    )
    
    external_image = SecureURLField(
        require_https=True,
        require_image_extension=True,
    )
```

### Method 3: Model Validators

Add validation at the model level:

```python
from django.db import models
from secure_uploads.validators import SecureImageValidator, SecureDocumentValidator

class Product(models.Model):
    title = models.CharField(max_length=200)
    
    image = models.ImageField(
        upload_to='products/',
        validators=[SecureImageValidator(
            max_size=5 * 1024 * 1024,
            allowed_extensions=['.jpg', '.png', '.webp'],
        )]
    )
    
    manual = models.FileField(
        upload_to='manuals/',
        validators=[SecureDocumentValidator(
            allowed_extensions=['.pdf'],
        )]
    )
```

### Method 4: Direct Validation Functions

Use validators directly in your views:

```python
from secure_uploads.validators import (
    validate_image_upload,
    validate_document_upload,
    validate_external_url,
    sanitise_filename,
)
from django.core.exceptions import ValidationError

def upload_view(request):
    if request.method == 'POST':
        file = request.FILES.get('image')
        
        try:
            # Validate the upload
            validate_image_upload(file)
            
            # Sanitise the filename
            file.name = sanitise_filename(file.name)
            
            # Safe to save
            # ...
            
        except ValidationError as e:
            return HttpResponse(f'Error: {e.message}', status=400)
```

---

## What Gets Validated

### For Images (`validate_image_upload`)

1. **File size** - Prevents memory exhaustion
2. **File extension** - First line of defence
3. **MIME type** - Reads actual file bytes, not just headers
4. **Image integrity** - PIL verifies it's a real, non-corrupted image
5. **Image dimensions** - Prevents billion-pixel attacks
6. **Embedded content** - Scans for PHP, JavaScript, shell commands

### For Documents (`validate_document_upload`)

1. **File size**
2. **File extension**
3. **MIME type**
4. **PDF-specific** - Blocks JavaScript and embedded files in PDFs
5. **Image validation** - If it's an image, runs image checks too

### For External URLs (`validate_external_url`)

1. **SSRF protection** - Blocks localhost, internal IPs, metadata endpoints
2. **Scheme validation** - HTTPS only by default
3. **Extension check** - Must point to valid image extension

---

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `SECURE_UPLOAD_MAX_FILE_SIZE` | 5MB | Maximum upload size in bytes |
| `SECURE_UPLOAD_MAX_IMAGE_DIMENSIONS` | (4096, 4096) | Maximum width/height |
| `SECURE_UPLOAD_MIN_IMAGE_DIMENSIONS` | (10, 10) | Minimum width/height |
| `SECURE_UPLOAD_ALLOWED_IMAGE_EXTENSIONS` | ['.jpg', '.jpeg', '.png', '.webp', '.gif'] | Allowed image extensions |
| `SECURE_UPLOAD_ALLOWED_IMAGE_MIME_TYPES` | ['image/jpeg', 'image/png', 'image/webp', 'image/gif'] | Allowed image MIME types |
| `SECURE_UPLOAD_ALLOWED_DOCUMENT_EXTENSIONS` | ['.pdf', '.jpg', '.jpeg', '.png', '.webp'] | Allowed document extensions |
| `SECURE_UPLOAD_ALLOWED_DOCUMENT_MIME_TYPES` | ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'] | Allowed document MIME types |
| `SECURE_UPLOAD_SANITISE_FILENAMES` | True | Replace original filenames with UUIDs |
| `SECURE_UPLOAD_REQUIRE_HTTPS_URLS` | True | Require HTTPS for external URLs |
| `SECURE_UPLOAD_BLOCKED_URL_HOSTS` | [see config.py] | Hosts blocked for SSRF protection |

---

## Nginx Configuration (Recommended)

Add these rules to prevent script execution in upload directories:

```nginx
# Disable script execution in media directories
location /media/ {
    location ~* \.(php|py|pl|sh|cgi)$ {
        deny all;
    }
    
    # Add security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Download-Options noopen;
}
```

---

## Testing Your Setup

```python
# test_security.py
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from secure_uploads.validators import validate_image_upload
from django.core.exceptions import ValidationError

class SecureUploadTests(TestCase):
    
    def test_rejects_php_disguised_as_jpg(self):
        """Malicious PHP file with .jpg extension should be rejected."""
        fake_image = SimpleUploadedFile(
            "hack.jpg",
            b"<?php echo 'pwned'; ?>",
            content_type="image/jpeg"
        )
        
        with self.assertRaises(ValidationError):
            validate_image_upload(fake_image)
    
    def test_rejects_oversized_file(self):
        """Files over the size limit should be rejected."""
        # Create a file that's too large
        large_content = b"x" * (6 * 1024 * 1024)  # 6MB
        large_file = SimpleUploadedFile(
            "large.jpg",
            large_content,
            content_type="image/jpeg"
        )
        
        with self.assertRaises(ValidationError):
            validate_image_upload(large_file)
```

---

## Changelog

### 1.0.0
- Initial release
- Image validation (extension, MIME, integrity, dimensions, embedded content)
- Document validation (PDF security checks)
- External URL validation (SSRF protection)
- Form mixins and secure field classes
- Model validators
- Middleware for request-level protection
- Configurable via Django settings

## What this module does not do

**It does not** manage authentication or permissions

**It does not** control who can download files

**It does not** replace Django’s storage backends

Its job is simple: ensure uploaded files are what they claim to be, and nothing more.

Diane Corriette
https://todiane.com 