# secure_uploads/forms.py
"""
Form mixins and fields for secure file uploads.
Drop-in replacements and mixins for Django forms.
"""

from django import forms
from django.core.exceptions import ValidationError

from .validators import (
    validate_image_upload,
    validate_document_upload,
    validate_external_url,
    sanitise_filename,
)
from .config import (
    get_max_file_size,
    get_allowed_image_extensions,
    get_allowed_image_mime_types,
    get_allowed_document_extensions,
    get_allowed_document_mime_types,
    get_sanitise_filenames,
)


# ============================================================================
# SECURE FORM FIELDS
# ============================================================================

class SecureImageField(forms.ImageField):
    """
    A secure ImageField that validates file content, not just extension.
    
    Usage:
        class MyForm(forms.Form):
            image = SecureImageField()
    """
    
    def __init__(self, *args, max_size=None, allowed_extensions=None,
                 allowed_mime_types=None, check_dimensions=True, 
                 sanitise_filename=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size
        self.allowed_extensions = allowed_extensions
        self.allowed_mime_types = allowed_mime_types
        self.check_dimensions = check_dimensions
        self.sanitise_filename = sanitise_filename
    
    def clean(self, data, initial=None):
        # First, run parent validation
        file = super().clean(data, initial)
        
        if file and hasattr(file, 'read'):
            # Run our comprehensive validation
            validate_image_upload(
                file,
                max_size=self.max_size,
                allowed_extensions=self.allowed_extensions,
                allowed_mime_types=self.allowed_mime_types,
                check_dimensions=self.check_dimensions
            )
            
            # Sanitise the filename
            if self.sanitise_filename and get_sanitise_filenames():
                file.name = sanitise_filename(file.name)
        
        return file


class SecureFileField(forms.FileField):
    """
    A secure FileField for documents (PDFs, receipts, etc.)
    
    Usage:
        class MyForm(forms.Form):
            receipt = SecureFileField()
    """
    
    def __init__(self, *args, max_size=None, allowed_extensions=None,
                 allowed_mime_types=None, sanitise_filename=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size
        self.allowed_extensions = allowed_extensions
        self.allowed_mime_types = allowed_mime_types
        self.sanitise_filename = sanitise_filename
    
    def clean(self, data, initial=None):
        file = super().clean(data, initial)
        
        if file and hasattr(file, 'read'):
            validate_document_upload(
                file,
                max_size=self.max_size,
                allowed_extensions=self.allowed_extensions,
                allowed_mime_types=self.allowed_mime_types
            )
            
            if self.sanitise_filename and get_sanitise_filenames():
                file.name = sanitise_filename(file.name)
        
        return file


class SecureURLField(forms.URLField):
    """
    A secure URLField for external image URLs with SSRF protection.
    
    Usage:
        class MyForm(forms.Form):
            external_image = SecureURLField(require_image_extension=True)
    """
    
    def __init__(self, *args, require_https=True, require_image_extension=True,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.require_https = require_https
        self.require_image_extension = require_image_extension
    
    def clean(self, value):
        url = super().clean(value)
        
        if url:
            validate_external_url(
                url,
                require_https=self.require_https,
                require_image_extension=self.require_image_extension
            )
        
        return url


# ============================================================================
# FORM MIXINS
# ============================================================================

class SecureImageUploadMixin:
    """
    Mixin to add secure image validation to any ModelForm.
    
    Usage:
        class LocationForm(SecureImageUploadMixin, forms.ModelForm):
            image_fields = ['image', 'thumbnail']  # Fields to validate
            
            class Meta:
                model = Location
                fields = ['title', 'image', 'thumbnail']
    
    Or override for custom settings per field:
        class LocationForm(SecureImageUploadMixin, forms.ModelForm):
            image_field_settings = {
                'image': {'max_size': 10 * 1024 * 1024},  # 10MB for main image
                'thumbnail': {'max_size': 1 * 1024 * 1024},  # 1MB for thumbnail
            }
    """
    
    # List of field names to validate as images
    image_fields = []
    
    # Optional per-field settings
    image_field_settings = {}
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Auto-detect image fields if not specified
        fields_to_check = self.image_fields or self._get_image_fields()
        
        for field_name in fields_to_check:
            if field_name in cleaned_data and cleaned_data[field_name]:
                file = cleaned_data[field_name]
                if hasattr(file, 'read'):
                    settings = self.image_field_settings.get(field_name, {})
                    try:
                        validate_image_upload(file, **settings)
                        
                        # Sanitise filename
                        if get_sanitise_filenames():
                            file.name = sanitise_filename(file.name)
                            
                    except ValidationError as e:
                        self.add_error(field_name, e)
        
        return cleaned_data
    
    def _get_image_fields(self):
        """Auto-detect ImageField fields in the form."""
        from django.db.models import ImageField
        
        image_fields = []
        
        if hasattr(self, 'Meta') and hasattr(self.Meta, 'model'):
            for field in self.Meta.model._meta.fields:
                if isinstance(field, ImageField) and field.name in self.fields:
                    image_fields.append(field.name)
        
        return image_fields


class SecureFileUploadMixin:
    """
    Mixin to add secure file validation to any ModelForm.
    Similar to SecureImageUploadMixin but for general file uploads.
    
    Usage:
        class ReceiptForm(SecureFileUploadMixin, forms.ModelForm):
            file_fields = ['receipt_image']
            
            class Meta:
                model = Receipt
                fields = ['description', 'receipt_image']
    """
    
    file_fields = []
    file_field_settings = {}
    
    def clean(self):
        cleaned_data = super().clean()
        
        fields_to_check = self.file_fields or self._get_file_fields()
        
        for field_name in fields_to_check:
            if field_name in cleaned_data and cleaned_data[field_name]:
                file = cleaned_data[field_name]
                if hasattr(file, 'read'):
                    settings = self.file_field_settings.get(field_name, {})
                    try:
                        validate_document_upload(file, **settings)
                        
                        if get_sanitise_filenames():
                            file.name = sanitise_filename(file.name)
                            
                    except ValidationError as e:
                        self.add_error(field_name, e)
        
        return cleaned_data
    
    def _get_file_fields(self):
        """Auto-detect FileField fields in the form."""
        from django.db.models import FileField
        
        file_fields = []
        
        if hasattr(self, 'Meta') and hasattr(self.Meta, 'model'):
            for field in self.Meta.model._meta.fields:
                if isinstance(field, FileField) and field.name in self.fields:
                    file_fields.append(field.name)
        
        return file_fields


class SecureExternalURLMixin:
    """
    Mixin to add SSRF protection to forms with external URL fields.
    
    Usage:
        class LocationForm(SecureExternalURLMixin, forms.ModelForm):
            url_fields = ['external_image_url']
            
            class Meta:
                model = Location
                fields = ['title', 'external_image_url']
    """
    
    url_fields = []
    url_field_settings = {}
    
    def clean(self):
        cleaned_data = super().clean()
        
        for field_name in self.url_fields:
            if field_name in cleaned_data and cleaned_data[field_name]:
                url = cleaned_data[field_name]
                settings = self.url_field_settings.get(field_name, {
                    'require_https': True,
                    'require_image_extension': True
                })
                try:
                    validate_external_url(url, **settings)
                except ValidationError as e:
                    self.add_error(field_name, e)
        
        return cleaned_data


# ============================================================================
# COMBINED MIXIN (most common use case)
# ============================================================================

class SecureUploadMixin(SecureImageUploadMixin, SecureFileUploadMixin, 
                        SecureExternalURLMixin):
    """
    Combined mixin that handles images, files, and URLs.
    
    Usage:
        class LocationForm(SecureUploadMixin, forms.ModelForm):
            image_fields = ['image']
            url_fields = ['external_image_url']
            
            class Meta:
                model = Location
                fields = ['title', 'image', 'external_image_url']
    """
    pass


# ============================================================================
# HELPER FUNCTION FOR QUICK FORM CREATION
# ============================================================================

def secure_modelform_factory(model, form=forms.ModelForm, fields=None, 
                             exclude=None, image_fields=None, file_fields=None,
                             url_fields=None, **kwargs):
    """
    Factory function to create a secure ModelForm for any model.
    
    Usage:
        from secure_uploads.forms import secure_modelform_factory
        
        LocationForm = secure_modelform_factory(
            Location,
            fields=['title', 'image', 'external_image_url'],
            image_fields=['image'],
            url_fields=['external_image_url']
        )
    """
    
    class SecureModelForm(SecureUploadMixin, form):
        class Meta:
            model_class = model
            model = model
            if fields:
                fields = fields
            if exclude:
                exclude = exclude
    
    if image_fields:
        SecureModelForm.image_fields = image_fields
    if file_fields:
        SecureModelForm.file_fields = file_fields
    if url_fields:
        SecureModelForm.url_fields = url_fields
    
    return SecureModelForm
