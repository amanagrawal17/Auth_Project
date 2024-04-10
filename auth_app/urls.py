'''this all modules are imported to use their functions.'''
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views 


urlpatterns = [
    path('register/' , views.register_view, name="register"),
    path('login/' , views.login_view, name="login"),
    path('logout/' , views.logout_view, name="logout"),
    path('home/', views.home_view, name='home'),
    # path('verify/email_token/', views.verify, name='verify'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    
    
    path('profile/', views.profile, name='profile'),
    path('password_change/', views.password_change, name='password_change'),
    path('password_reset/',auth_views.PasswordResetView.as_view(template_name="auth/password_reset_form.html"),name='password_reset'),
    path('password_reset/done/',auth_views.PasswordResetDoneView.as_view(template_name="auth/password_reset_done.html"),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name="auth/password_reset_confirm.html"),name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(template_name="auth/password_reset_complete.html"),name='password_reset_complete')
]
 