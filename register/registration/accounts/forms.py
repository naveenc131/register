from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.contrib.auth.models import User

class RegistrationForm(UserCreationForm):
    username = forms.CharField(label="username",
            widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    email = forms.EmailField(label = "Email",
        widget=forms.TextInput(attrs={'placeholder': 'Email'}))
    first_name = forms.CharField( max_length=30,
        widget=forms.TextInput(attrs={'placeholder': 'First Name'}))
    last_name = forms.CharField( max_length=150,
        widget=forms.TextInput(attrs={'placeholder': 'last Name'}))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder' : 'Password'}))
    password2 = forms.CharField(label="re-enter password",widget = forms.PasswordInput(attrs={'placeholder' : 'Renter_password'}))


    class Meta:
        model = User
        fields = ("username","email","first_name","last_name")

class Login(forms.Form):
    username = forms.CharField(max_length=254)
    password = forms.CharField(widget=forms.PasswordInput)

class PasswordRequestSet(forms.Form):
    email = forms.EmailField(label = "Email",
        widget=forms.TextInput(attrs={'placeholder': 'Email'}))

class PasswordResetForm(forms.Form):
    new_password1 = forms.CharField(widget=forms.PasswordInput(attrs=
        {'placeholder' : 'Password'}))
    new_password2 = forms.CharField(label="re-enter password",
        widget = forms.PasswordInput(attrs={'placeholder' : 'Renter_password'}))

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                    )
        return password2




    



