# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#

from oic.oic.message import TokenErrorResponse

class TooBusyError(RuntimeError):
    pass

class TooManyRequestsFromOrigin(RuntimeError):
    pass

# pylint: disable=too-many-ancestors
class TokenSAMLErrorResponse(TokenErrorResponse):
    c_allowed_values = TokenErrorResponse.c_allowed_values.copy()
    c_allowed_values.update(
    {
        "error": [
            "saml_authn_failed",
        ]
    }
)
