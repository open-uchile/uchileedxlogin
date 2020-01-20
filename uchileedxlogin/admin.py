from django.contrib import admin
from .models import EdxLoginUser, EdxLoginUserCourseRegistration

# Register your models here.
admin.site.register(EdxLoginUser)
admin.site.register(EdxLoginUserCourseRegistration)