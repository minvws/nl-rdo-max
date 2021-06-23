# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#

from pyop.exceptions import OAuthError

class UserNotAuthenticated(OAuthError):
    pass

class ValidationError(RuntimeError):
    pass
