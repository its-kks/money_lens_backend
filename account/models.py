from django.db import models

from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# custom user manager
class UserManager(BaseUserManager):
    def create_user(self, email, username,  avatar, password=None, password2=None):
        """
        Creates and saves a User with the given email, username, avatar
        and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            avatar=avatar

            
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, avatar, password=None):
        """
        Creates and saves a superuser with the given email, username, avatar
        and password.
        """
        user = self.create_user(
            email,
            password=password,
            username=username,
            avatar=avatar
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
  email = models.EmailField(
      verbose_name="Email",
      max_length=255,
      unique=True,
  )
  username = models.CharField(max_length=255)
  avatar = models.CharField(max_length=255)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = "email"
  REQUIRED_FIELDS = ["username", "avatar"]

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin
  