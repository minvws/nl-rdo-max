# class MetaRedirectResponse(HTMLResponse):
#     def __init__(
#         self,
#         redirect_url: str,
#         status_code: int = 200,
#         headers: dict = None,
#         media_type: str = None,
#         background: BackgroundTask = None,
#
#     ) -> None:
#         self.redirect_url = redirect_url
#         self.template = os.path.join(
#             ROOT_DIR, "templates/saml/html/assertion_consumer_service.html"
#         )
#
#         content = self.create_acs_redirect_link({"redirect_url": self.redirect_url})
#         super().__init__(
#             content=content,
#             status_code=status_code,
#             headers=headers,
#             media_type=media_type,
#             background=background,
#         )
#
#     def create_acs_redirect_link(self, context: dict) -> typing.Text:
#         return _fill_template_from_file(self.template, context)