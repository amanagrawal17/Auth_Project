''' modules imported to use their functions'''
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm,SetPasswordForm


class LoginForm(forms.Form):
    '''stores the value/input getting from the user  '''
    username = forms.CharField(max_length=65)
    password = forms.CharField(max_length=65, widget=forms.PasswordInput)

class RegisterForm(UserCreationForm):
    '''stores the user details in user feilds '''
    first_name =forms.CharField(max_length=65)
    last_name =forms.CharField(max_length=65)
    class Meta:
        ''' defines the models'''
        model=User
        fields = ['username','email','password1','password2','first_name','last_name']
  
class SetPasswordForm(SetPasswordForm):
    class Meta:
        model = User()
        fields = ['new_password1', 'new_password2']