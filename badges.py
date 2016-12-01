#!/usr/bin/env python3
from marathon import *
from wsgiref.simple_server import make_server
import svgwrite
import svgwrite.masking
import svgwrite.path
import svgwrite.text
import svgwrite.container
import svgwrite.gradients
import svgwrite.shapes

import argparse
import logging
import cachetools.func
import falcon
from pprint import pprint

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logger = logging.getLogger(__name__)


class WebApp(object):
    __ttl = 60
    __cachesize = 1024

    def __init__(self, marathon):
        self.__marathon = marathon

    def service(self, req, resp):

        if req.path.startswith('/service/'):
            app_id = req.path[9:]
            if app_id.endswith('.svg'):
                app_id = app_id[:-4]
            resp.content_type = 'image/svg+xml'
            resp.body = self.render(app_id)

    @cachetools.func.ttl_cache(maxsize=__cachesize, ttl=__ttl)
    def render(self, app_id):
        try:
            app = self.__marathon.get_app(app_id)
            tasks = {
                'total': app['instances'],
                'healthy': app['tasksHealthy'],
                'running': app['tasksRunning'],
                'staged': app['tasksStaged'],
                'unhealthy': app['tasksUnhealthy'],
            }
            if tasks['total'] == tasks['healthy']:
                color = 'lima'
            elif tasks['total'] == tasks['running']:
                color = 'lochmara'
            elif tasks['running'] > 0:
                color = 'gold_tips'
            elif tasks['running'] == 0:
                color = 'crimson'
            else:
                color = 'silver_chalice'

            key = 'status'

            if tasks['total'] == 0:
                value = 'suspended'
                color = 'silver_chalice'
            else:
                value = '{}/{}'.format(tasks['running'], tasks['total'])

            return badge(color, key, value)

        except requests.exceptions.HTTPError as e:
            logger.error(e)
            if e.response.status_code == 404:
                return badge('silver_chalice', 'status', 'unknown')


class HealthCheck(object):
    def on_get(self, req, resp):
        resp.content_type = 'text/plain'
        resp.body = 'ok\r\n'


def badge(color, ltext, rtext):
    width = 128
    height = 20
    colors = {
        'lima': '#76bd17',
        'pistachio': '#9dc209',
        'silver_chalice': '#acacac',
        'flame_pea': '#da5b38',
        'gold_tips': '#deba13',
        'citron': '#9ea91f',
        'crusta': '#fd7b33',
        'lochmara': '#007ec7',
        'crimson': '#dc143c'
    }
    svg = svgwrite.Drawing(size=(width, height))

    gradient = svgwrite.gradients.LinearGradient(end=(0, '100%'), id='gradient')
    gradient.add_stop_color(offset=0, color='#bbb', opacity=.01)
    gradient.add_stop_color(offset=1, opacity=0.1)

    mask = svgwrite.masking.Mask(id='mask')
    mask.add(svgwrite.shapes.Rect(size=(width, height), rx=3, fill='#fff'))

    bg_group = svgwrite.container.Group(mask='url(#mask)')
    left_box = svgwrite.path.Path(d='M0 0h59v{}H0z'.format(height), fill='#555')
    right_box = svgwrite.path.Path(d='M59 0h69v{}H59z'.format(height), fill=colors[color])
    overlay = svgwrite.path.Path(d='M0 0h{}v{}H0z'.format(width, height), fill='url(#gradient)')
    bg_group.add(left_box)
    bg_group.add(right_box)
    bg_group.add(overlay)

    text_group = svgwrite.container.Group(fill='#fff', text_anchor='middle',
                                          font_family='DejaVu Sans,Verdana,Geneva,sans-serif',
                                          font_size=11)
    left_text_shadow = svgwrite.text.Text(x=[29.5], y=[15], fill='#010101', opacity=0.3, text=ltext)
    left_text = svgwrite.text.Text(x=[29.5], y=[14], text=ltext)
    right_text_shadow = svgwrite.text.Text(x=[92.5], y=[15], fill='#010101', opacity=0.3, text=rtext)
    right_text = svgwrite.text.Text(x=[92.5], y=[14], text=rtext)
    text_group.add(left_text_shadow)
    text_group.add(left_text)
    text_group.add(right_text_shadow)
    text_group.add(right_text)

    svg.add(gradient)
    svg.add(mask)
    svg.add(bg_group)
    svg.add(text_group)
    return svg.tostring()


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="DC/OS Badges",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--marathon', '-m',
                        nargs="+",
                        help='Marathon endpoint, eg. -m http://marathon1:8080 http://marathon2:8080',
                        default=['http://master.mesos:8080'],
                        required=True
                        )
    parser.add_argument('--port', '-p', help='TCP Port to listen on', default=80, type=int)
    parser = set_marathon_auth_args(parser)
    return parser


if __name__ == '__main__':
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    marathon = Marathon(args.marathon,
                        get_marathon_auth_params(args),
                        args.marathon_ca_cert)
    api = falcon.API()
    webapp = WebApp(marathon)
    api.add_sink(webapp.service, '/service')
    api.add_route('/health', HealthCheck())
    httpd = make_server('', args.port, api)
    print('Serving on port {}...'.format(args.port))
    httpd.serve_forever()
