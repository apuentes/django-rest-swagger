import json
from django.utils import six

from django.conf import settings
from django.views.generic import View
from django.utils.safestring import mark_safe
from django.utils.encoding import smart_text
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.core.exceptions import PermissionDenied
from django.contrib.sites.shortcuts import get_current_site
from .compat import import_string

from collections import OrderedDict

from rest_framework.views import Response
from rest_framework.settings import api_settings
from rest_framework.utils import formatting

from rest_framework_swagger.urlparser import UrlParser
from rest_framework_swagger.apidocview import APIDocView
from rest_framework_swagger.docgenerator import DocumentationGenerator

import rest_framework_swagger as rfs


try:
    JSONRenderer = list(filter(
        lambda item: item.format == 'json',
        api_settings.DEFAULT_RENDERER_CLASSES,
    ))[0]
except IndexError:
    from rest_framework.renderers import JSONRenderer


def get_restructuredtext(view_cls, html=False):
    from docutils import core

    description = view_cls.__doc__ or ''
    description = formatting.dedent(smart_text(description))
    if html:
        parts = core.publish_parts(source=description, writer_name='html')
        html = parts['body_pre_docinfo'] + parts['fragment']
        return mark_safe(html)
    return description


def get_full_base_path(request):
    try:
        base_path = rfs.SWAGGER_SETTINGS['base_path']
    except KeyError:
        return request.build_absolute_uri(request.path).rstrip('/')
    else:
        protocol = 'https' if request.is_secure() else 'http'
        return '{0}://{1}'.format(protocol, base_path.rstrip('/'))


class SwaggerUIView(View):
    def get(self, request, *args, **kwargs):

        if not self.has_permission(request):
            return self.handle_permission_denied(request)

        template_name = rfs.SWAGGER_SETTINGS.get('template_path')
        data = {
            'swagger_settings': {
                'discovery_url': "%s/api-docs/" % get_full_base_path(request),
                'api_key': rfs.SWAGGER_SETTINGS.get('api_key', ''),
                'api_version': rfs.SWAGGER_SETTINGS.get('api_version', ''),
                'token_type': rfs.SWAGGER_SETTINGS.get('token_type'),
                'enabled_methods': mark_safe(
                    json.dumps(rfs.SWAGGER_SETTINGS.get('enabled_methods'))),
                'doc_expansion': rfs.SWAGGER_SETTINGS.get('doc_expansion', ''),
            },
            'rest_framework_settings': {
                'DEFAULT_VERSIONING_CLASS':
                    settings.REST_FRAMEWORK.get('DEFAULT_VERSIONING_CLASS', '')
                    if hasattr(settings, 'REST_FRAMEWORK') else None,

            },
            'django_settings': {
                'CSRF_COOKIE_NAME': mark_safe(
                    json.dumps(getattr(settings, 'CSRF_COOKIE_NAME', 'csrftoken'))),
            }
        }
        response = render_to_response(
            template_name, RequestContext(request, data))

        return response

    def has_permission(self, request):
        if rfs.SWAGGER_SETTINGS.get('is_superuser') and \
                not request.user.is_superuser:
            return False

        if rfs.SWAGGER_SETTINGS.get('is_authenticated') and \
                not request.user.is_authenticated():
            return False

        return True

    def handle_permission_denied(self, request):
        permission_denied_handler = rfs.SWAGGER_SETTINGS.get(
            'permission_denied_handler')
        if isinstance(permission_denied_handler, six.string_types):
            permission_denied_handler = import_string(
                permission_denied_handler)

        if permission_denied_handler:
            return permission_denied_handler(request)
        else:
            raise PermissionDenied()


class SwaggerResourcesView(APIDocView):
    renderer_classes = (JSONRenderer, )

    def get(self, request, *args, **kwargs):
        apis = [{'path': '/' + path} for path in self.get_resources()]
        return Response({
            'apiVersion': rfs.SWAGGER_SETTINGS.get('api_version', ''),
            'swaggerVersion': '1.2',
            'basePath': self.get_base_path(),
            'apis': apis,
            'info': rfs.SWAGGER_SETTINGS.get('info', {
                'contact': '',
                'description': '',
                'license': '',
                'licenseUrl': '',
                'termsOfServiceUrl': '',
                'title': '',
            }),
        })

    def get_base_path(self):
        try:
            base_path = rfs.SWAGGER_SETTINGS['base_path']
        except KeyError:
            return self.request.build_absolute_uri(
                self.request.path).rstrip('/')
        else:
            protocol = 'https' if self.request.is_secure() else 'http'
            return '{0}://{1}/{2}'.format(protocol, base_path, 'api-docs')

    def get_resources(self):
        urlparser = UrlParser()
        urlconf = getattr(self.request, "urlconf", None)
        exclude_url_names = rfs.SWAGGER_SETTINGS.get('exclude_url_names')
        exclude_namespaces = rfs.SWAGGER_SETTINGS.get('exclude_namespaces')
        apis = urlparser.get_apis(urlconf=urlconf, exclude_url_names=exclude_url_names,
                                  exclude_namespaces=exclude_namespaces)
        authorized_apis = filter(lambda a: self.handle_resource_access(self.request, a['pattern']), apis)
        authorized_apis_list = list(authorized_apis)
        resources = urlparser.get_top_level_apis(authorized_apis_list)
        return resources


class SwaggerApiView(APIDocView):
    renderer_classes = (JSONRenderer, )

    def get(self, request, path, *args, **kwargs):
        apis = self.get_apis_for_resource(path)
        generator = DocumentationGenerator(for_user=request.user)
        return Response({
            'apiVersion': rfs.SWAGGER_SETTINGS.get('api_version', ''),
            'swaggerVersion': '1.2',
            'basePath': self.api_full_uri.rstrip('/'),
            'resourcePath': '/' + path,
            'apis': generator.generate(apis),
            'models': generator.get_models(apis),
        })

    def get_apis_for_resource(self, filter_path):
        urlparser = UrlParser()
        urlconf = getattr(self.request, "urlconf", None)
        exclude_url_names = rfs.SWAGGER_SETTINGS.get('exclude_url_names')
        exclude_namespaces = rfs.SWAGGER_SETTINGS.get('exclude_namespaces')
        apis = urlparser.get_apis(urlconf=urlconf, filter_path=filter_path,
                                  exclude_url_names=exclude_url_names,
                                  exclude_namespaces=exclude_namespaces)
        authorized_apis = filter(lambda a: self.handle_resource_access(self.request, a['pattern']), apis)
        authorized_apis_list = list(authorized_apis)
        return authorized_apis_list


class AWSSwaggerAPIView(APIDocView):
    renderer_classes = (JSONRenderer, )

    def get(self, request, *args, **kwargs):
        apis = self.get_apis()
        generator = DocumentationGenerator(for_user=request.user)
        apis_explained = generator.generate(apis)
        apis_models = generator.get_models(apis)
        with_cors = request.REQUEST.get('cors', False)

        current_site = get_current_site(request)
        scheme, host = self.get_base_path()

        result = OrderedDict()
        result['swagger'] = '2.0'
        result['info'] = {
            'title': current_site.name,
            'description': current_site.domain,
            'version': rfs.SWAGGER_SETTINGS.get('api_version', '')
        }
        result['host'] = host
        result['basePath'] = '/'
        result['securityDefinitions'] = {}
        result['schemes'] = [
            scheme
        ]
        result['paths'] = self.get_paths(apis_explained, apis_models, scheme, host, with_cors)
        result['definitions'] = self.get_definitions(apis_models, with_cors)

        return Response(result)

    def get_apis(self):
        urlparser = UrlParser()
        urlconf = getattr(self.request, "urlconf", None)
        exclude_url_names = rfs.SWAGGER_SETTINGS.get('exclude_url_names')
        exclude_namespaces = rfs.SWAGGER_SETTINGS.get('exclude_namespaces')
        apis = urlparser.get_apis(urlconf=urlconf, exclude_url_names=exclude_url_names,
                                  exclude_namespaces=exclude_namespaces)
        authorized_apis = filter(lambda a: self.handle_resource_access(self.request, a['pattern']), apis)
        authorized_apis_list = list(authorized_apis)
        return authorized_apis_list

    def get_base_path(self):
        try:
            base_path = rfs.SWAGGER_SETTINGS['base_path'].rstrip('/')
        except KeyError:
            base_path = self.request.build_absolute_uri(
                self.request.path).rstrip('/')
            protocol, base_path = base_path.split('://')
            base_path = base_path.split('/', 1)[0]
            return protocol, base_path
        else:
            protocol = 'https' if self.request.is_secure() else 'http'
            return protocol, base_path

    def get_paths(self, apis_explained, apis_models, scheme, host, with_cors=False):
        paths = {}
        for api in apis_explained:
            path = {}
            for method in api['operations']:
                params = [{
                    'name': 'Authorization',
                    'in': 'header',
                    'required': False,
                    'type': 'string'
                }]
                aws_params = {
                    'integration.request.header.Accept': '\'application/json\'',
                    'integration.request.header.Authorization': 'method.request.header.Authorization'
                }
                for param in method['parameters']:
                    if param['paramType'] != 'form':
                        params.append({
                            'name': param['name'],
                            'in': param['paramType'],
                            'required': param.get('required', False),
                            'type': param['type'],
                            'description': ''
                        })
                        param_type = param['paramType'] if param['paramType'] != 'query' else 'querystring'
                        aws_params['integration.request.%s.%s' % (param_type, param['name'])] = \
                            'method.request.%s.%s' % (param_type, param['name'])
                response_schema = {
                    'type': method['type']
                }
                if method['type'] == 'array':
                    response_schema = {
                        'type': 'array',
                        'items': method['items']
                    }
                elif method['type'] in apis_models:
                    response_schema = {
                        '$ref': method['type']
                    }
                path_method = {
                    'description': method['summary'],
                    'operationId': method['nickname'],
                    'parameters': params,
                    'responses': {
                        '200': {
                            'description': '',
                            'schema': response_schema
                        }
                    },
                    'x-amazon-apigateway-integration': {
                        'type': 'http',
                        'uri': '%s://%s%s' % (scheme, host, api['path']),
                        'httpMethod': method['method'].upper(),
                        'responses': {
                            'default': {
                                'statusCode': '200'
                            }
                        },
                        'requestParameters': aws_params
                    }
                }
                path[method['method'].lower()] = path_method
            if with_cors:
                path['options'] = {
                    'responses': {
                        '200': {
                            'description': '200 response',
                            'schema': {
                                '$ref': '#/definitions/Empty'
                            },
                            'headers': {
                                'Access-Control-Allow-Origin': {
                                    'type': 'string'
                                },
                                'Access-Control-Allow-Methods': {
                                    'type': 'string'
                                },
                                'Access-Control-Allow-Headers': {
                                    'type': 'string'
                                }
                            }
                        }
                    },
                    'x-amazon-apigateway-integration': {
                        'responses': {
                            'default': {
                                'statusCode": "200",
                                'responseParameters": {
                                    'method.response.header.Access-Control-Allow-Methods': '\'%s\'' % ','.join(api['operations'].keys()),
                                    'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token\'',
                                    'method.response.header.Access-Control-Allow-Origin': '\'*\''
                                }
                            }
                        },
                        'requestTemplates': {
                            'application/json': '{"statusCode": 200}'
                        },
                        'type': 'mock'
                    }
                }
            paths[api['path']] = path
        self.check_definitions(paths)
        return paths

    def get_definitions(self, apis_models, with_cors=False):
        definitions = {}
        for key in apis_models:
            model = apis_models[key]
            props = {}
            for prop_key in model['properties']:
                props[prop_key] = model['properties'][prop_key]
                props[prop_key]['description'] = str(props[prop_key]['description']) if props[prop_key]['description'] else ''
                try:
                    del props[prop_key]['required']
                    del props[prop_key]['readOnly']
                except:
                    pass
                if props[prop_key]['type'] in apis_models:
                    props[prop_key]['$ref'] = props[prop_key]['type']
                    del props[prop_key]['type']
            definitions[model['id']] = {
                'properties': model['properties']
            }
        if with_cors:
            definitions['Empty'] = {
                'type': 'object'
            }
        self.check_definitions(definitions)
        return definitions

    def check_definitions(self, dictionary):
        for key in dictionary:
            if key == '$ref':
                if not dictionary[key].startswith('#'):
                    dictionary[key] = '#/definitions/%s' % dictionary[key]
            elif type(dictionary[key]) in [dict, OrderedDict]:
                self.check_definitions(dictionary[key])
