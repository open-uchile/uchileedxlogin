from django.contrib import admin
from .models import EdxLoginUser, EdxLoginUserCourseRegistration

# Register your models here.

class EdxLoginUserAdmin(admin.ModelAdmin):
    list_display = ('run', 'user')
    search_fields = ['run', 'user']
    ordering = ['-run']

class EdxLoginUserCourseRegistrationAdmin(admin.ModelAdmin):
    list_display = ('run', 'course')
    search_fields = ['run', 'course']
    ordering = ['-course']

admin.site.register(EdxLoginUser, EdxLoginUserAdmin)
admin.site.register(EdxLoginUserCourseRegistration, EdxLoginUserCourseRegistrationAdmin)