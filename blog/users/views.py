import re

from django.contrib.auth import logout
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse

from django.views import View
from users.models import User
from django.db import DatabaseError


# 注册视图
class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        """
        1.接收数据
        2.验证数据
            2.1参数是否齐全
            2.2手机号格式是否正确
            2.3密码是否符合格式
            2.4密码确认密码一致
            2.5短信验证码是否和redis中一致
        3.保存注册信息
        4.返回响应跳转到指定页面
        """

        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #   2.1参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要的参数')
        #   2.2手机号格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #   2.3密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #   2.4密码确认密码一致
        if password != password2:
            return HttpResponseBadRequest('密码不一致')
        #   2.5短信验证码是否和redis中一致
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码过期')
        if smscode != redis_sms_code.decode():  # redis中存放的是字符串编码，需要解码
            return HttpResponseBadRequest('验证码不一致')
        # 3.保存注册信息
        # craete_user可以使用系统的方法对密码进行加密
        try:
            user = User.objects.create_user(username=mobile, mobile=mobile, password=password)
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')

        # 实现状态保持
        from django.contrib.auth import login
        login(request, user)

        # 4.返回响应跳转到指定页面
        # 暂时返回成功信息，后期跳转到指定页面

        # redirect重定向  reverse可以通过namespce:name来获取视图所对应的路由
        response = redirect(reverse('home:index'))
        # 设置cookie
        # 登录状态 会话结束自动过期
        response.set_cookie('is_login', True)
        # 设置用户名有效期一个月
        response.set_cookie('username', user, max_age=30 * 24 * 3600)
        # return HttpResponse('注册成功，跳转到首页')
        return response


from django.http.response import HttpResponseBadRequest
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection
from django.http import HttpResponse


class ImageCodeView(View):
    def get(self, request):
        """
        1.接受前端传过来的uuid
        2.判断uuid是否获取到
        3.通过调用captcha来生成图片验证码（图片二进制和图片内容）
        4.将图片内容保存到redis中
            uuid作为key，图片内容为value，同时还需要一个时效
        5.返回图片二进制
        :param request;
        :return;
        """
        # 1.接受前端传过来的uuid
        uuid = request.GET.get('uuid')
        # 2.判断uuid是否获取到
        if uuid is None:
            return HttpResponseBadRequest('没有传递uuid')
        # 3.通过调用captcha来生成图片验证码（图片二进制和图片内容）
        text, image = captcha.generate_captcha()
        # 4.将图片内容保存到redis中
        #       uuid作为key，图片内容为value，同时还需要一个时效
        redis_conn = get_redis_connection('default')
        # key 设置为uuid
        # seconds 过期秒数 300s
        # value text
        redis_conn.setex('img:%s' % uuid, 300, text)
        # 5.返回图片二进制
        return HttpResponse(image, content_type='image/jpeg')


from django.http.response import JsonResponse
from utils.response_code import RETCODE

import logging

logger = logging.getLogger('django')

from random import randint
from libs.yuntongxun.sms import CCP


class SmsCodeView(View):
    def get(self, request):
        """
        1.接受参数
        2.参数的验证
            2.1验证参数是否齐全
            2.2图片验证码的验证
                链接redis，获取redis中图片验证码
                判断图片验证码是否存在
                如果图片验证码未过期，我们获取到后可以删除图片验证码
                比对图片验证码（注意大小写）
        3.生成短信验证码
        4.保存短信验证码到redis
        5.发送短信
        6.返回响应
        """

        # 1.接受参数
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        # 2.参数的验证
        #     2.1验证参数是否齐全
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要参数'})
        #     2.2图片验证码的验证
        #         链接redis，获取redis中图片验证码
        redis_conn = get_redis_connection('default')
        redis_image_code = redis_conn.get('img:%s' % uuid)
        #         判断图片验证码是否存在
        if redis_image_code is None:
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码过期'})
        #         如果图片验证码未过期，我们获取到后可以删除图片验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        #         比对图片验证码（注意大小写）redis数据是bytes类型
        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证失败'})
        # 3.生成短信验证码
        sms_code = '%06d' % randint(0, 999999)
        # 为了后期对比方便，可以把短信验证码记录到日志中
        logger.info(sms_code)
        # 4.保存短信验证码到redis
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 5.发送短信
        CCP().send_template_sms(mobile, [sms_code, 5], 1)
        # 6.返回响应
        # 参数一：测试手机号
        # 参数二：列表  {1}为短信验证码  {2}为短信有效时间
        # 参数三：免费测试使用的模板id
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功！'})


class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        '''
        1.接受参数
        2.校验参数
            2.1手机号验证是否符合规则
            2.2密码是否符合规则
        3.用户认证登录
        4.状态保持
        5.根据用户选择的是否记住登陆状态判断
        6.为了首页显示需要设置一些cookie信息
        7.返回响应
        '''

        # 1.接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        # 2.校验参数
        #     2.1手机号验证是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.2密码是否符合规则
        if not re.match(r'^[a-zA-Z0-9]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合规则')
        # 3.用户认证登录
        # 采用系统自带的认证方式
        # 如果用户名密码正确，返回user
        # 如果用户名或密码错误，返回None
        from django.contrib.auth import authenticate
        # 默认的认证方法是针对于username字段进行用户名的判断
        # 当前的判断信息是mobile，所以需要修改认证字段
        # 需要到模型中修改（user.model）,等测试的时候修改
        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或者密码错误')
        # 4.状态保持
        from django.contrib.auth import login
        login(request, user)
        # 5.根据用户选择的是否记住登陆状态判断
        # 6.为了首页显示需要设置一些cookie信息
        # 根据next参数进行页面跳转
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))
        if remember != 'on':  # 没有记住
            # 浏览器关闭后
            request.session.set_expiry(0)
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:  # 记住
            # m默认记住两周
            request.session.set_expiry(None)
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        # 7.返回响应
        return response


class LogoutView(View):
    def get(self, request):
        # 1.session数据清除
        logout(request)
        # 2.删除部分cookie数据
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        # 3.跳转到首页
        return response


class ForgetPasswordView(View):
    def get(self, request):
        return render(request, 'forget_password.html')

    def post(self, request):
        """
        1.获取参数
        2.参数校验
            2.1判断参数齐全
            2.2手机号是否符合规则
            2.3密码是否符合规则
            2.4密码与确认密码是否一致
            2.5判断短信验证码是否正确
        3.根据手机号进行用户信息查询
        4.如果查询出用户信息则修改
        5.如果没有查询到信息，则新用户创建
        6.可以进行页面的跳转
        7.返回响应
        """
        # 1.获取参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.参数校验
        #   2.1判断参数齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要的参数')
            #   2.2手机号格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
            #   2.3密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
            #   2.4密码确认密码一致
        if password != password2:
            return HttpResponseBadRequest('密码不一致')
            # 2.5判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码过期')
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5.如果没有查询到信息，则新用户创建
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，平稍后再试')
        else:
            # 4.如果查询出用户信息则修改
            user.set_password(password)
            user.save()
        # 6.可以进行页面的跳转
        response = redirect(reverse('users:login'))
        # 7.返回响应
        return response


from django.contrib.auth.mixins import LoginRequiredMixin


# LoginRequiredMixin
# 如果用户未登录，则会默认跳转
# 默认跳转链接：accounts/login/?next=xxx    可以去settings.py中修改
class UserCenterView(LoginRequiredMixin, View):
    def get(self, request):
        # if request.user.is_authenticated:#如果登录返回true
        #     return render(request, 'center.html')
        # else:
        #     return render(request,'login.html')
        # 获取登录用户信息
        user = request.user
        # 组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc,
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        """
        1.接受参数
        2.将参数保存
        3.更新一下cookie信息username
        4.刷新当前页面（重定向）
        5.返回响应
        """
        # 1.接受参数
        user = request.user
        username = request.POST.get('username', user.username)  # 第一个参数为表单提交，第二个是当表单没有提交,为之前的值
        user_desc = request.POST.get('desc', user.user_desc)
        avatar = request.FILES.get('avatar')
        # 2.将参数保存
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('修改失败，请稍后再试')
        # 3.更新一下cookie信息username
        # 4.刷新当前页面（重定向）
        response = redirect(reverse('users:center'))
        response.set_cookie('username', user.username, max_age=14 * 3600 * 24)
        # 5.返回响应
        return response


from home.models import ArticleCategory, Article


class WriteBlogView(LoginRequiredMixin, View):
    def get(self, request):
        # 查询所有分类模型
        categories = ArticleCategory.objects.all()

        # 获取登录用户信息
        # user = request.user
        # 组织获取用户的信息
        context = {
            # 'username': user.username,
            # 'mobile': user.mobile,
            # 'avatar': user.avatar.url if user.avatar else None,
            # 'user_desc': user.user_desc,
            'categories': categories
        }
        return render(request, 'write_blog.html', context=context)

    def post(self, request):
        """
        1.接受数据
        2.校验数据
        3.数据入库
        4.跳转到指定页面（暂时首页）
        """
        # 1.接受数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user
        # 2.校验数据
        # 2.1验证参数齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全')
        # 2.2判断分类id
        try:
            category = ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有改分类')
        # 3.数据入库
        try:
            article = Article.objects.create(
                author=user,
                avatar=avatar,
                title=title,
                category=category,
                tags=tags,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，稍后重试')
        # 4.跳转到指定页面（暂时首页）
        return redirect(reverse('home:index'))
