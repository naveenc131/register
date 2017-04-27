from django.conf.urls import url,include
from .views import HomePageView
from .views import SignUpView,LoginView,PasswordRequestView,PasswordResetDone,PasswordResetConfirm

urlpatterns = [
    
    url('^$', HomePageView.as_view(), name='home'),
    url(r'^signup/$', SignUpView.as_view(), name='signup'),
    url(r'^login/$', LoginView.as_view(), name='login'),
    url(r'^forget/$',PasswordRequestView.as_view(),name='forget'),
    url(r'^forget/password_reset_done$',PasswordResetDone.as_view(),name='done'),
    url(r'^password_reset_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$',PasswordResetConfirm.as_view(),name='password_reset_confirm'),

]