"""aurora_back URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import login
from .views import signup
from .views import password_reset
from .views import password_change
from .views import delete_user

# from .views import (login, signup, password_reset, 
#                     password_change, delete_user)
from .views import admin_list
from .views import admin_create
from .views import admin_detail_search
from .views import admin_detail_revise
from .views import parent_list
from .views import parent_detail_search


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/login/', login, name='login'),
    path('api/signup/', signup, name='signup'),
    path('api/password_reset/', password_reset, name='password_reset'),
    path('api/password_change/', password_change, name='password_change'),
    path('api/delete_user/', delete_user, name='delete_user'),
    
    path('api/admin_list/', admin_list, name='admin_list'),
    path('api/admin_create/', admin_create, name='admin_create'),
    path('api/admin_detail_search/', admin_detail_search, name='admin_detail_search'),
    path('api/admin_detail_revise/', admin_detail_revise, name='admin_detail_revise'),
    path('api/parent_list/', parent_list, name='parent_list'),
    path('api/parent_detail_search/', parent_detail_search, name='parent_detail_search'),
#    path('api/profile/', profile, name='profile'),

]