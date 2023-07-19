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
from .views import evaluator_list
from .views import evaluator_detail_search
from .views import evaluator_detail_revise

from .views import child_list
from .views import child_create
from .views import child_detail_search
from .views import child_detail_revise

urlpatterns = [
    path('admin/', admin.site.urls),

    # path('api/login/', login, name='login'),
    # path('api/signup/', signup, name='signup'),
    # path('api/password_reset/', password_reset, name='password_reset'),
    # path('api/password_change/', password_change, name='password_change'),
    # path('api/delete_user/', delete_user, name='delete_user'),

    path('api/public/login', login, name='login'),
    path('api/public/signup', signup, name='signup'),
    path('api/public/password-reset', password_reset, name='password_reset'),
    path('api/public/password-change', password_change, name='password_change'),
    path('api/public/delete-user', delete_user, name='delete_user'),


    # path('api/admin_list/', admin_list, name='admin_list'),
    # path('api/admin_create/', admin_create, name='admin_create'),
    # path('api/admin_detail_search/', admin_detail_search, name='admin_detail_search'),
    # path('api/admin_detail_revise/', admin_detail_revise, name='admin_detail_revise'),
    # path('api/parent_list/', parent_list, name='parent_list'),
    # path('api/parent_detail_search/', parent_detail_search, name='parent_detail_search'),

    path('api/admin-list', admin_list, name='admin_list'),
    path('api/admin-create', admin_create, name='admin_create'),
    path('api/admin-detail-search', admin_detail_search, name='admin_detail_search'),
    path('api/admin-detail-revise', admin_detail_revise, name='admin_detail_revise'),
    path('api/parent-list', parent_list, name='parent_list'),
    path('api/parent-detail-search', parent_detail_search, name='parent_detail_search'),
    path('api/evaluator-list', evaluator_list, name='evaluator_list'),
    path('api/evaluator-detail-search', evaluator_detail_search, name='evaluator_detail_search'),
    path('api/evaluator-detail-revise', evaluator_detail_revise, name='evaluator_detail_revise'),

    path('api/child-list', child_list, name='child_list'),
    path('api/child-create', child_create, name='child_create'),
    path('api/child-detail-search', child_detail_search, name='child_detail_search'),
    path('api/child-detail-revise', child_detail_revise, name='child_detail_revise'),

#    path('api/profile/', profile, name='profile'),

]
