from __future__ import absolute_import
from django.shortcuts import render
from django.views import generic
from django.views import View
from django.http import HttpResponseRedirect
from .forms import RegistrationForm,Login,PasswordRequestSet,PasswordResetForm
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse_lazy
from django.contrib.auth import authenticate, login
from django.template import loader
from django.contrib.auth.tokens import default_token_generator
from django.db.models.query import Q
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings

# Create your views here.
class HomePageView(generic.TemplateView):
	template_name = 'home.html'

class PasswordResetDone(generic.TemplateView):
	template_name = 'password_reset_done.html'

class PasswordResetConfirm(generic.TemplateView):
	template_name = 'password_reset_confirm.html'

class SignUpView(generic.CreateView):
	model = User
	form_class = RegistrationForm
	template_name = 'signup.html'
	success_url = '/'
	def form_valid(self,form):
		user = User.objects.create_user(form.cleaned_data['username'],
                                        form.cleaned_data['email'],
                                        form.cleaned_data['password1'])
		user.save()
		return HttpResponseRedirect(self.success_url)
	



class LoginView(generic.FormView):
	template_name = 'login.html'
	form_class = Login
	success_url = '/'
	def form_valid(self,form):

		username = form.cleaned_data['username']
		password = form.cleaned_data['password']
		user = authenticate(username = username, password = password)
		if user is not None:
			login(self.request,user)
			return super(LoginView,self).form_valid(form)
		else:
			return self.form_invalid(form)

class PasswordRequestView(generic.FormView):
	template_name = 'password_reset_form.html'
	form_class = PasswordRequestSet
	success_url = 'password_reset_done'

	@staticmethod
	def validate_email(email):
		try:
			validate_email(email)
			return True
		except ValidationError:
			return False

	def post(self,request,*args,**kwargs):
		form = self.form_class(request.POST)
		try:
			if form.is_valid():
				data = form.cleaned_data["email"]
			if self.validate_email(data) is True:
					users = User.objects.filter(
						Q(email = data)
						)
					if users.exists():
						for user in users:
							self.reset_password(user,request)
						result = self.form_valid(form)
						return result
					result = self.form_invalid(form)
					return result
		except Exception as e:
			print(e)
		return self.form_invalid(form)

	def reset_password(self,user,request):
		context = {
			'email' : user.email,
			'domain': request.META['HTTP_HOST'],
			'uid'   : urlsafe_base64_encode(force_bytes(user.pk)),
			'user'  : user,
			'token' : default_token_generator.make_token(user),
			'protocol': 'http',
			}

		subject_template_name = 'password_reset_subject.txt'

		email_template_name = 'password_reset_email.html'

		subject = loader.render_to_string(subject_template_name,context)

		subject = ''.join(subject.splitlines())

		email = loader.render_to_string(email_template_name,context)

		send_mail(subject,email,settings.DEFAULT_FROM_EMAIL,[user.email],
				fail_silently=False)

class PasswordResetView(generic.FormView):
	template_name = "password_reset_confirm.html"
	success_url = "/admin/"
	form_class = PasswordResetForm

	def post(self,request,uidb64=None,token=None,*arg,**kwargs):
		UserModel = get_user_model()
		form = self.form_class(request.POST)
		assert uidb64 is not None and token is not None
		try:
			uid = urlsafe_base64_decode(uidb64)
			user = UserModel._default_manager.get(pk=uid)
		except(TypeError,ValueError,OverflowError,UserModel.DoesNotExist):
			user = None
		if user is not None and default_token_generator.check_token(user,token):
			if form.is_valid():
				new_password = form.cleaned_data['new_passowrd2']
				user.set_password(new_password)
				user.save()
				messages.success(request,'password has been reset')
				return self.form_valid(form)
			else:
				messages.error(
					request,'Password reset Unsuccessful'
					)
				return self.form_invalid(form)
		else:
			messages.error(request,'the link is decativated')
			return self.form_invalid(form)


					










