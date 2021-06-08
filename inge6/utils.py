from jinja2 import Template
from .config import settings

def create_post_autosubmit_form(context):
    with open(settings.saml.authn_request_html_template) as template_file:
        template_text = template_file.read()

    template = Template(template_text)
    html = template.render(context)

    return html
