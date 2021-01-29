# 主要是用于users子应用路由
from django.urls import path
from users.views import RegisterView, ImageCodeView, SmsCodeView, LoginView, LogoutView

urlpatterns = [
    # path的第一个参数：路由
    # path的第二个参数：视图函数名
    path('register/', RegisterView.as_view(), name='register'),
    # 图片验证码路由
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),
    # 短信验证码路由
    path('smscode/', SmsCodeView.as_view(), name='smscode'),
    # 登陆路由
    path('login/', LoginView.as_view(), name='login'),
    # 登出路由
    path('logout/', LogoutView.as_view(), name='logout'),

]
