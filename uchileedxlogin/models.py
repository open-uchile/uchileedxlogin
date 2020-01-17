from django.contrib.auth.models import User
from django.db import models

from opaque_keys.edx.django.models import CourseKeyField

# Create your models here.


class EdxLoginUser(models.Model):    
    run = models.CharField(max_length=18, unique=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=False, null=False)

