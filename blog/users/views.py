from django.shortcuts import render

# Create your views here.

from django.views import View


# 注册视图
class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')


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
