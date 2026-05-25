from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from unfold.admin import ModelAdmin
from unfold.forms import AdminPasswordChangeForm, UserChangeForm, UserCreationForm
from .models import (
    User, Tenant, UserProfile, MagicLinkToken, EmailVerificationToken,
    PasswordResetToken, UserRefreshToken, Role, Permission,
    UserRoleAssignment, UserMFA
)

# ------------------------------------------------------------
# Custom User Admin (Unfold styled)
# ------------------------------------------------------------
# Unregister the default User admin (if already registered)
try:
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass

@admin.register(User)
class UserAdmin(BaseUserAdmin, ModelAdmin):
    # Use Unfold's forms for proper styling
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm

    list_display = ('email', 'full_name', 'tenant', 'role', 'is_active', 'is_email_verified')
    list_filter = ('role', 'is_active', 'is_email_verified', 'tenant')
    search_fields = ('email', 'full_name')
    ordering = ('email',)
    
    # Make auto-generated fields read-only
    readonly_fields = ('last_login', 'created_at', 'deleted_at')

    fieldsets = (
        (None, {'fields': ('email', 'full_name', 'password')}),
        ('Permissions', {
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser'),
            'description': 'Roles are assigned via UserRoleAssignment, not here directly.'
        }),
        ('Security', {'fields': ('failed_login_attempts', 'locked_until', 'last_login_ip')}),
        ('Tenant', {'fields': ('tenant',)}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'deleted_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'password1', 'password2', 'tenant', 'role'),
        }),
    )
    
    filter_horizontal = ()
# ------------------------------------------------------------
# Other ModelAdmins – simply change the base class to ModelAdmin
# ------------------------------------------------------------
@admin.register(Tenant)
class TenantAdmin(ModelAdmin):
    list_display = ('name', 'slug', 'subscription_tier', 'created_at')
    search_fields = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}
    list_filter = ('subscription_tier',)

@admin.register(UserProfile)
class UserProfileAdmin(ModelAdmin):
    list_display = ('user', 'phone_number', 'city', 'country')
    search_fields = ('user__email', 'user__full_name', 'phone_number')
    list_filter = ('country', 'timezone')

@admin.register(MagicLinkToken)
class MagicLinkTokenAdmin(ModelAdmin):
    list_display = ('user', 'is_valid', 'expires_at', 'used', 'created_at')
    list_filter = ('used', 'expires_at')
    search_fields = ('user__email', 'token_hash')
    readonly_fields = ('token_hash', 'created_at', 'used_at')

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(ModelAdmin):
    list_display = ('user', 'is_valid', 'expires_at', 'used', 'created_at')
    list_filter = ('used', 'expires_at')
    search_fields = ('user__email',)

@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(ModelAdmin):
    list_display = ('user', 'is_valid', 'expires_at', 'used', 'created_at')
    list_filter = ('used', 'expires_at')
    search_fields = ('user__email',)

@admin.register(UserRefreshToken)
class UserRefreshTokenAdmin(ModelAdmin):
    list_display = ('user', 'device_name', 'revoked', 'expires_at', 'last_used_at')
    list_filter = ('revoked', 'expires_at')
    search_fields = ('user__email', 'device_name', 'jti')
    readonly_fields = ('jti', 'created_at', 'last_used_at')

@admin.register(Role)
class RoleAdmin(ModelAdmin):
    list_display = ('name', 'description', 'created_at')
    search_fields = ('name',)
    filter_horizontal = ('permissions',)

@admin.register(Permission)
class PermissionAdmin(ModelAdmin):
    list_display = ('codename', 'name', 'resource_type')
    search_fields = ('codename', 'name')
    list_filter = ('resource_type',)

@admin.register(UserRoleAssignment)
class UserRoleAssignmentAdmin(ModelAdmin):
    list_display = ('user', 'role', 'assigned_by', 'assigned_at', 'expires_at', 'is_active')
    list_filter = ('role', 'expires_at')
    search_fields = ('user__email', 'role__name')
    raw_id_fields = ('user', 'assigned_by')
    readonly_fields = ('assigned_at',)

@admin.register(UserMFA)
class UserMFAAdmin(ModelAdmin):
    list_display = ('user', 'method', 'is_active', 'created_at')
    list_filter = ('method', 'is_active')
    search_fields = ('user__email',)
    readonly_fields = ('secret_encrypted', 'backup_codes_hash')