"""aurora_back URL Configuration
"""
from django.contrib import admin
from django.urls import path
from .views import login
from .views import signup
from .views import password_reset
from .views import password_change
from .views import delete_user


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

from .views import asset_list
from .views import asset_revise
from .views import asset_upload
from .views import delete_asset

from .views import content_upload
from .views import content_list
from .views import content_detail_list
from .views import content_detail_revise

from .views import creativity_charsi_list
from .views import creativity_file_save

urlpatterns = [
    path('admin/', admin.site.urls),

    path('api/public/login', login, name='login'),
    path('api/public/signup', signup, name='signup'),
    path('api/public/password-reset', password_reset, name='password_reset'),
    path('api/public/password-change', password_change, name='password_change'),
    path('api/public/delete-user', delete_user, name='delete_user'),


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


    path('api/asset-list', asset_list, name='asset_list'),
    path('api/asset-revise', asset_revise, name='asset_revise'),    
    path('api/asset-upload', asset_upload, name='asset_upload'),
    path('api/delete-asset', delete_asset, name='delete_asset'),

    path('api/content-upload', content_upload, name='content_upload'),

    path('api/content-list', content_list, name='content_list'),
    path('api/content-detail-list', content_detail_list, name='content_detail_list'),
    path('api/content-detail-revise', content_detail_revise, name='content_detail_revise'),

    path('api/creativity-charsi-list', creativity_charsi_list, name='creativity_charsi_list'),    
    path('api/content-detail-revise', creativity_file_save, name='creativity_file_save'),
]
