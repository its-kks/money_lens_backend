from django.contrib import admin
from account.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

 
class UserModalAdmin(BaseUserAdmin):

  # The fields to be used in displaying the User model.
  # These override the definitions on the base UserModalAdmin
  # that reference specific fields on auth.User.
  list_display = ["id", "email", "username", "avatar" ,"is_admin"]
  list_filter = ["is_admin"]
  fieldsets = [
      ('User Credentials', {"fields": ["email", "password"]}),
      ("Personal info", {"fields": ["avatar", "username"]}),
      ("Permissions", {"fields": ["is_admin"]}),
  ]
  # add_fieldsets is not a standard ModelAdmin attribute. UserModalAdmin
  # overrides get_fieldsets to use this attribute when creating a user.
  add_fieldsets = [
      (
          None,
          {
              "classes": ["wide"],
              "fields": ["email", "username", "avatar", "password1", "password2"],
          },
      ),
  ]
  search_fields = ["email"]
  ordering = ["email"]
  filter_horizontal = []


# Now register the new UserModalAdmin...
admin.site.register(User, UserModalAdmin)
# Register your models here.
