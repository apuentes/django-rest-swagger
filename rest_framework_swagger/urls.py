from django.conf.urls import url
from rest_framework_swagger.views import SwaggerResourcesView, SwaggerApiView, SwaggerUIView, AWSSwaggerAPIView


urlpatterns = [
    url(r'^$', SwaggerUIView.as_view(), name="django.swagger.base.view"),
    url(r'^api-docs/$', SwaggerResourcesView.as_view(), name="django.swagger.resources.view"),
    url(r'^api-docs/(?P<path>.*)/?$', SwaggerApiView.as_view(), name='django.swagger.api.view'),
    url(r'^api-docs-aws/$', AWSSwaggerAPIView.as_view(), name='django.swagger.api.aws.view'),
]
